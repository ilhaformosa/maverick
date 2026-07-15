#![deny(unsafe_op_in_unsafe_fn)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

use tokio::io::unix::AsyncFd;

pub(super) struct TunEndpoint {
    file: AsyncFd<File>,
    name: String,
}

impl TunEndpoint {
    pub(super) fn open_existing(name: &str) -> io::Result<Self> {
        validate_name(name)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")?;

        // SAFETY: `request` is zero-initialized as required by TUNSETIFF. The
        // name is bounded to IFNAMSIZ - 1 bytes, the file descriptor is owned
        // for this call, and the kernel receives a valid mutable ifreq pointer.
        let request = unsafe {
            let mut request: libc::ifreq = std::mem::zeroed();
            for (destination, source) in request.ifr_name.iter_mut().zip(name.bytes()) {
                *destination = source as libc::c_char;
            }
            request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
            let result = libc::ioctl(
                file.as_raw_fd(),
                libc::TUNSETIFF as libc::c_ulong,
                &mut request,
            );
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            request
        };

        let actual_name = request
            .ifr_name
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect::<Vec<_>>();
        let actual_name = String::from_utf8(actual_name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "TUN name is not UTF-8"))?;
        if actual_name != name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel attached a different TUN device",
            ));
        }

        Ok(Self {
            file: AsyncFd::new(file)?,
            name: actual_name,
        })
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.file.readable().await?;
            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                file.read(buffer)
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    pub(super) async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.file.writable().await?;
            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                file.write(packet)
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid TUN device name",
        ));
    }
    Ok(())
}
