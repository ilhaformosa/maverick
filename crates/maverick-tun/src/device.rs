use std::collections::VecDeque;

use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

pub(crate) struct BoundedDevice {
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
    queue_limit: usize,
    mtu: usize,
}

impl BoundedDevice {
    pub(crate) fn new(mtu: usize, queue_limit: usize) -> Self {
        Self {
            incoming: VecDeque::with_capacity(queue_limit),
            outgoing: VecDeque::with_capacity(queue_limit),
            queue_limit,
            mtu,
        }
    }

    pub(crate) fn admit(&mut self, packet: Vec<u8>) -> Result<(), Vec<u8>> {
        if self.incoming.len() >= self.queue_limit {
            return Err(packet);
        }
        self.incoming.push_back(packet);
        Ok(())
    }

    pub(crate) fn take_outgoing(&mut self) -> Option<Vec<u8>> {
        self.outgoing.pop_front()
    }

    pub(crate) fn put_outgoing_front(&mut self, packet: Vec<u8>) {
        self.outgoing.push_front(packet);
    }

    pub(crate) fn buffered_bytes(&self) -> usize {
        self.incoming
            .iter()
            .chain(self.outgoing.iter())
            .map(Vec::len)
            .sum()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.incoming.is_empty() && self.outgoing.is_empty()
    }
}

pub(crate) struct DeviceRx(Vec<u8>);

pub(crate) struct DeviceTx<'a> {
    outgoing: &'a mut VecDeque<Vec<u8>>,
}

impl RxToken for DeviceRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for DeviceTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.outgoing.push_back(packet);
        result
    }
}

impl Device for BoundedDevice {
    type RxToken<'a> = DeviceRx;
    type TxToken<'a> = DeviceTx<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.outgoing.len() >= self.queue_limit {
            return None;
        }
        let packet = self.incoming.pop_front()?;
        Some((
            DeviceRx(packet),
            DeviceTx {
                outgoing: &mut self.outgoing,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.outgoing.len() >= self.queue_limit {
            return None;
        }
        Some(DeviceTx {
            outgoing: &mut self.outgoing,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }
}
