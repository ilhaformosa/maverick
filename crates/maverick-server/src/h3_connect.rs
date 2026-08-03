use maverick_core::frame::TargetAddr;
use std::error::Error as StdError;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

const MAX_AUTHORITY_LEN: usize = 259;
const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ClassicConnectParseError;

impl fmt::Debug for ClassicConnectParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid H3 request metadata")
    }
}

impl fmt::Display for ClassicConnectParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid H3 request metadata")
    }
}

impl StdError for ClassicConnectParseError {}

pub(crate) fn parse_classic_connect_request(
    headers: &[(&[u8], &[u8])],
) -> Result<(TargetAddr, u16), ClassicConnectParseError> {
    if headers.len() != 2 {
        return Err(ClassicConnectParseError);
    }

    let mut method_seen = false;
    let mut authority = None;
    for &(name, value) in headers {
        match name {
            b":method" if !method_seen && value == b"CONNECT" => method_seen = true,
            b":authority" if authority.is_none() => authority = Some(value),
            _ => return Err(ClassicConnectParseError),
        }
    }

    if !method_seen {
        return Err(ClassicConnectParseError);
    }
    parse_authority(authority.ok_or(ClassicConnectParseError)?)
}

fn parse_authority(authority: &[u8]) -> Result<(TargetAddr, u16), ClassicConnectParseError> {
    if authority.is_empty()
        || authority.len() > MAX_AUTHORITY_LEN
        || !authority.is_ascii()
        || authority.iter().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(*byte, b'@' | b'/' | b'?' | b'#' | b'\\' | b'%')
        })
    {
        return Err(ClassicConnectParseError);
    }

    if authority.starts_with(b"[") {
        return parse_bracketed_ipv6(authority);
    }

    let separator = authority
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(ClassicConnectParseError)?;
    let host = &authority[..separator];
    let port = &authority[separator + 1..];
    if host.is_empty() || port.contains(&b':') {
        return Err(ClassicConnectParseError);
    }
    let port = parse_port(port)?;

    if host
        .iter()
        .all(|byte| byte.is_ascii_digit() || *byte == b'.')
    {
        return Ok((TargetAddr::Ipv4(parse_ipv4(host)?), port));
    }
    if looks_like_noncanonical_numeric_host(host) {
        return Err(ClassicConnectParseError);
    }

    Ok((TargetAddr::Domain(parse_domain(host)?), port))
}

fn parse_bracketed_ipv6(authority: &[u8]) -> Result<(TargetAddr, u16), ClassicConnectParseError> {
    let closing = authority
        .iter()
        .position(|byte| *byte == b']')
        .ok_or(ClassicConnectParseError)?;
    if closing <= 1 || authority.get(closing + 1) != Some(&b':') {
        return Err(ClassicConnectParseError);
    }

    let address = std::str::from_utf8(&authority[1..closing])
        .map_err(|_| ClassicConnectParseError)
        .and_then(|value| Ipv6Addr::from_str(value).map_err(|_| ClassicConnectParseError))?;
    let port = parse_port(&authority[closing + 2..])?;
    Ok((TargetAddr::Ipv6(address), port))
}

fn parse_port(port: &[u8]) -> Result<u16, ClassicConnectParseError> {
    if port.is_empty()
        || port.len() > 5
        || !port.iter().all(u8::is_ascii_digit)
        || (port.len() > 1 && port[0] == b'0')
    {
        return Err(ClassicConnectParseError);
    }

    let mut value = 0_u32;
    for byte in port {
        value = value * 10 + u32::from(*byte - b'0');
    }
    if value == 0 || value > u32::from(u16::MAX) {
        return Err(ClassicConnectParseError);
    }
    Ok(value as u16)
}

fn parse_ipv4(host: &[u8]) -> Result<Ipv4Addr, ClassicConnectParseError> {
    let mut segments = host.split(|byte| *byte == b'.');
    let mut octets = [0_u8; 4];
    for octet in &mut octets {
        let segment = segments.next().ok_or(ClassicConnectParseError)?;
        if segment.is_empty() || segment.len() > 3 || (segment.len() > 1 && segment[0] == b'0') {
            return Err(ClassicConnectParseError);
        }
        let mut value = 0_u16;
        for byte in segment {
            value = value * 10 + u16::from(*byte - b'0');
        }
        if value > u16::from(u8::MAX) {
            return Err(ClassicConnectParseError);
        }
        *octet = value as u8;
    }
    if segments.next().is_some() {
        return Err(ClassicConnectParseError);
    }
    Ok(Ipv4Addr::from(octets))
}

fn looks_like_noncanonical_numeric_host(host: &[u8]) -> bool {
    let mut saw_hex = false;
    let all_numeric_components = host.split(|byte| *byte == b'.').all(|label| {
        if !label.is_empty() && label.iter().all(u8::is_ascii_digit) {
            return true;
        }
        if label.len() > 2
            && label[0] == b'0'
            && matches!(label[1], b'x' | b'X')
            && label[2..].iter().all(u8::is_ascii_hexdigit)
        {
            saw_hex = true;
            return true;
        }
        false
    });
    all_numeric_components && saw_hex
}

fn parse_domain(host: &[u8]) -> Result<String, ClassicConnectParseError> {
    if host.is_empty() || host.len() > MAX_DOMAIN_LEN {
        return Err(ClassicConnectParseError);
    }
    for label in host.split(|byte| *byte == b'.') {
        if label.is_empty()
            || label.len() > MAX_LABEL_LEN
            || !label[0].is_ascii_alphanumeric()
            || !label[label.len() - 1].is_ascii_alphanumeric()
            || !label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err(ClassicConnectParseError);
        }
    }

    std::str::from_utf8(host)
        .map(str::to_ascii_lowercase)
        .map_err(|_| ClassicConnectParseError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(authority: &[u8]) -> [(&[u8], &[u8]); 2] {
        [
            (b":method".as_slice(), b"CONNECT".as_slice()),
            (b":authority".as_slice(), authority),
        ]
    }

    fn assert_authority_rejected(authority: &[u8]) {
        assert_eq!(
            parse_classic_connect_request(&headers(authority)),
            Err(ClassicConnectParseError)
        );
    }

    #[test]
    fn parses_strict_classic_connect_domain_authority() {
        assert_eq!(
            parse_classic_connect_request(&headers(b"Example.Invalid:443")),
            Ok((TargetAddr::Domain("example.invalid".to_owned()), 443))
        );
        assert_eq!(
            parse_classic_connect_request(&headers(b"a:1")),
            Ok((TargetAddr::Domain("a".to_owned()), 1))
        );
        assert_eq!(
            parse_classic_connect_request(&headers(b"XN--EXAMPLE-9D0B.INVALID:65535")),
            Ok((
                TargetAddr::Domain("xn--example-9d0b.invalid".to_owned()),
                65_535
            ))
        );
    }

    #[test]
    fn parses_canonical_ipv4_and_bracketed_ipv6() {
        assert_eq!(
            parse_classic_connect_request(&headers(b"192.0.2.1:443")),
            Ok((TargetAddr::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443))
        );
        assert_eq!(
            parse_classic_connect_request(&headers(b"[2001:db8::1]:65535")),
            Ok((
                TargetAddr::Ipv6(Ipv6Addr::from_str("2001:db8::1").unwrap()),
                65_535
            ))
        );
    }

    #[test]
    fn accepts_both_pseudo_header_orders_with_the_same_result() {
        let method_first = headers(b"Order.Invalid:443");
        let authority_first = [method_first[1], method_first[0]];
        assert_eq!(
            parse_classic_connect_request(&method_first),
            parse_classic_connect_request(&authority_first)
        );
    }

    #[test]
    fn rejects_missing_duplicate_unknown_and_noncanonical_fields() {
        let cases: Vec<Vec<(&[u8], &[u8])>> = vec![
            vec![],
            vec![(b":method", b"CONNECT")],
            vec![(b":authority", b"example.invalid:443")],
            vec![(b":method", b"CONNECT"), (b":method", b"CONNECT")],
            vec![
                (b":authority", b"example.invalid:443"),
                (b":authority", b"example.invalid:443"),
            ],
            vec![(b":method", b"CONNECT"), (b":unknown", b"x")],
            vec![(b":method", b"CONNECT"), (b"x-extra", b"1")],
            vec![(b":method", b"CONNECT"), (b":scheme", b"https")],
            vec![(b":method", b"CONNECT"), (b":path", b"/")],
            vec![(b":method", b"CONNECT"), (b":protocol", b"connect-udp")],
            vec![(b":method", b"CONNECT"), (b"host", b"example.invalid")],
            vec![
                (b":method", b"connect"),
                (b":authority", b"example.invalid:443"),
            ],
            vec![
                (b":method", b"GET"),
                (b":authority", b"example.invalid:443"),
            ],
            vec![
                (b":Method", b"CONNECT"),
                (b":authority", b"example.invalid:443"),
            ],
            vec![
                (b":method", b"CONNECT"),
                (b":Authority", b"example.invalid:443"),
            ],
            vec![(b"", b"CONNECT"), (b":authority", b"example.invalid:443")],
            vec![(b":method", b""), (b":authority", b"example.invalid:443")],
            vec![(b":method", b"CONNECT"), (b":authority", b"")],
            vec![
                (b":method", b"CONNECT"),
                (b":authority", b"example.invalid:443"),
                (b"x-extra", b"1"),
            ],
        ];

        for case in cases {
            assert_eq!(
                parse_classic_connect_request(&case),
                Err(ClassicConnectParseError)
            );
        }
    }

    #[test]
    fn rejects_authority_envelope_ambiguity_and_unsafe_bytes() {
        for authority in [
            b"user@example.invalid:443".as_slice(),
            b"example.invalid:443/path",
            b"example.invalid:443?query",
            b"example.invalid:443#fragment",
            b"https://example.invalid:443",
            b"example.invalid\\name:443",
            b" example.invalid:443",
            b"example.invalid :443",
            b"example.invalid:\t443",
            b"example.invalid:\r443",
            b"example.invalid:\n443",
            b"example.invalid:\x00443",
            b"example.invalid:\x1f443",
            b"example.invalid:\x7f443",
            b"example.\xff:443",
        ] {
            assert_authority_rejected(authority);
        }

        let mut overlong = vec![b'a'; MAX_AUTHORITY_LEN + 1];
        overlong[MAX_AUTHORITY_LEN - 1] = b':';
        assert_authority_rejected(&overlong);
    }

    #[test]
    fn rejects_missing_noncanonical_and_out_of_range_ports() {
        for authority in [
            b"example.invalid".as_slice(),
            b"example.invalid:",
            b"example.invalid:0",
            b"example.invalid:00",
            b"example.invalid:01",
            b"example.invalid:0443",
            b"example.invalid:65536",
            b"example.invalid:999999",
            b"example.invalid:+443",
            b"example.invalid:-1",
            b"example.invalid: 443",
        ] {
            assert_authority_rejected(authority);
        }
    }

    #[test]
    fn rejects_ambiguous_and_noncanonical_ipv4_forms() {
        for authority in [
            b"127.1:443".as_slice(),
            b"127:443",
            b"127.0.0.1.:443",
            b"1.2.3:443",
            b"1.2.3.4.5:443",
            b"1..2.3:443",
            b"256.0.0.1:443",
            b"999.1.1.1:443",
            b"01.2.3.4:443",
            b"1.02.3.4:443",
            b"0177.0.0.1:443",
            b"0x7f000001:443",
            b"0x7f.0.0.1:443",
            b"0X7F.0X0.0X0.0X1:443",
        ] {
            assert_authority_rejected(authority);
        }
    }

    #[test]
    fn rejects_unbracketed_or_non_ipv6_literal_forms() {
        for authority in [
            b"2001:db8::1:443".as_slice(),
            b"[fe80::1%25en0]:443",
            b"[fe80::1%en0]:443",
            b"[v1.example]:443",
            b"[127.0.0.1]:443",
            b"[::1]x:443",
            b"[::1]:443x",
            b"[::1:443",
            b"::1]:443",
        ] {
            assert_authority_rejected(authority);
        }
    }

    #[test]
    fn rejects_empty_oversize_or_invalid_domain_labels() {
        for authority in [
            b":443".as_slice(),
            b".example.invalid:443",
            b"example..invalid:443",
            b"example.invalid.:443",
            b"under_score.invalid:443",
            b"-leading.invalid:443",
            b"trailing-.invalid:443",
            b"invalid!.example:443",
            b"example[1].invalid:443",
        ] {
            assert_authority_rejected(authority);
        }

        let oversize_label = format!("{}.invalid:443", "a".repeat(MAX_LABEL_LEN + 1));
        assert_authority_rejected(oversize_label.as_bytes());
        let oversize_domain = format!(
            "{}.{}.{}.{}:1",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(oversize_domain.len() - 2, MAX_DOMAIN_LEN + 1);
        assert_authority_rejected(oversize_domain.as_bytes());
    }

    #[test]
    fn accepts_the_maximum_length_domain_authority() {
        let domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let authority = format!("{domain}:65535");
        assert_eq!(domain.len(), MAX_DOMAIN_LEN);
        assert_eq!(authority.len(), MAX_AUTHORITY_LEN);
        assert_eq!(
            parse_classic_connect_request(&headers(authority.as_bytes())),
            Ok((TargetAddr::Domain(domain), 65_535))
        );
    }

    #[test]
    fn errors_are_fixed_bounded_value_free_and_source_free() {
        let marker = "MALICIOUS_SYNTHETIC_MARKER";
        let oversized = format!("{marker}\n\x1b[31m{}:443", "x".repeat(4_096));
        let cases: Vec<Vec<(&[u8], &[u8])>> = vec![
            vec![
                (marker.as_bytes(), b"CONNECT"),
                (b":authority", b"safe.invalid:443"),
            ],
            vec![
                (b":method", marker.as_bytes()),
                (b":authority", b"safe.invalid:443"),
            ],
            vec![
                (b":method", b"CONNECT"),
                (b":authority", oversized.as_bytes()),
            ],
        ];

        for case in cases {
            let error = parse_classic_connect_request(&case).unwrap_err();
            assert!(StdError::source(&error).is_none());
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert_eq!(rendered, "invalid H3 request metadata");
                assert!(rendered.len() <= 32);
                for forbidden in [marker, "safe.invalid", "443", "\n", "\x1b", "x-extra"] {
                    assert!(!rendered.contains(forbidden));
                }
            }
        }
    }
}
