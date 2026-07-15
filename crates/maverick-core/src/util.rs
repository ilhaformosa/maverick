use std::net::IpAddr;

pub fn redact_id(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    if chars.len() <= 6 {
        return "***".into();
    }
    let start: String = chars.iter().take(4).collect();
    let end: String = chars
        .iter()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{start}...{end}")
}

pub fn redact_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            format!("{}.{}.x.x", octets[0], octets[1])
        }
        IpAddr::V6(addr) => {
            let segments = addr.segments();
            format!("{:x}:{:x}:****", segments[0], segments[1])
        }
    }
}
