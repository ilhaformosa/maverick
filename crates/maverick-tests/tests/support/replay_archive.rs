use flate2::{Compression, GzBuilder};
use std::io::Write;

pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), Compression::new(6));
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn write_octal(field: &mut [u8], value: u64) {
    let digits = format!("{:0width$o}", value, width = field.len() - 1);
    assert_eq!(digits.len(), field.len() - 1);
    field[..digits.len()].copy_from_slice(digits.as_bytes());
    field[field.len() - 1] = 0;
}

pub fn tar_header(path: &str, bytes: &[u8], kind: u8) -> [u8; 512] {
    assert!(path.len() <= 100);
    let mut header = [0_u8; 512];
    header[..path.len()].copy_from_slice(path.as_bytes());
    write_octal(&mut header[100..108], 0o600);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], bytes.len() as u64);
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = kind;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let checksum_text = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum_text.as_bytes());
    header
}

pub fn synthetic_tar() -> Vec<u8> {
    let entries = [
        ("synthetic-0.0.0/LICENSE", b"synthetic license\n".as_slice()),
        ("synthetic-0.0.0/src/message.txt", b"before\n".as_slice()),
    ];
    let mut tar = Vec::new();
    for (path, bytes) in entries {
        tar.extend_from_slice(&tar_header(path, bytes, b'0'));
        tar.extend_from_slice(bytes);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.extend_from_slice(&[0; 1024]);
    tar
}
