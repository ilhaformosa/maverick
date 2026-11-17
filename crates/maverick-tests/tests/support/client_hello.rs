//! Bounded field location for generated local ClientHello fixtures. No names
//! or handshake bytes are returned in experiment reports.
use anyhow::{ensure, Context, Result};
use std::ops::Range;

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, size: usize) -> Result<&'a [u8]> {
    let end = cursor.checked_add(size).context("field length overflow")?;
    let value = bytes
        .get(*cursor..end)
        .context("truncated ClientHello field")?;
    *cursor = end;
    Ok(value)
}

fn u16_at(bytes: &[u8], cursor: &mut usize) -> Result<usize> {
    let value = take(bytes, cursor, 2)?;
    Ok(u16::from_be_bytes([value[0], value[1]]) as usize)
}

pub fn sni_range(handshake: &[u8]) -> Result<Range<usize>> {
    ensure!((4..=16_384).contains(&handshake.len()) && handshake[0] == 1);
    let length = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
    ensure!(length + 4 == handshake.len(), "incomplete ClientHello");
    let mut cursor = 4;
    take(handshake, &mut cursor, 34)?; // legacy version and random
    let session_length = take(handshake, &mut cursor, 1)?[0] as usize;
    take(handshake, &mut cursor, session_length)?;
    let ciphers = u16_at(handshake, &mut cursor)?;
    take(handshake, &mut cursor, ciphers)?;
    let compression = take(handshake, &mut cursor, 1)?[0] as usize;
    take(handshake, &mut cursor, compression)?;
    let extensions = u16_at(handshake, &mut cursor)?;
    ensure!(cursor + extensions == handshake.len());
    while cursor < handshake.len() {
        let kind = u16_at(handshake, &mut cursor)?;
        let length = u16_at(handshake, &mut cursor)?;
        let start = cursor;
        let extension = take(handshake, &mut cursor, length)?;
        if kind == 0 {
            let mut name = 0;
            let list_length = u16_at(extension, &mut name)?;
            ensure!(list_length + 2 == extension.len());
            ensure!(take(extension, &mut name, 1)?[0] == 0);
            let name_length = u16_at(extension, &mut name)?;
            ensure!(name_length > 1 && name + name_length == extension.len());
            return Ok(start + name..start + name + name_length);
        }
    }
    anyhow::bail!("fixture has no SNI")
}
