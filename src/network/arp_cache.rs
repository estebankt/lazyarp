use std::net::Ipv4Addr;

/// Read the kernel ARP table without elevated privileges.
pub fn read_arp_cache(iface_name: &str) -> Vec<(Ipv4Addr, [u8; 6])> {
    #[cfg(target_os = "linux")]
    return read_arp_cache_linux(iface_name);

    #[cfg(target_os = "macos")]
    return read_arp_cache_macos(iface_name);

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = iface_name;
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn read_arp_cache_linux(iface_name: &str) -> Vec<(Ipv4Addr, [u8; 6])> {
    let content = match std::fs::read_to_string("/proc/net/arp") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();
    // Format: IP  HW-type  Flags  HW-addr  Mask  Device
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let ip_str = fields[0];
        let flags_str = fields[2];
        let mac_str = fields[3];
        let device = fields[5];

        if device != iface_name {
            continue;
        }

        // Only keep complete entries (Flags & 0x2)
        let flags = u32::from_str_radix(flags_str.trim_start_matches("0x"), 16).unwrap_or(0);
        if flags & 0x2 == 0 {
            continue;
        }

        if let (Some(ip), Some(mac)) = (parse_ipv4(ip_str), parse_mac(mac_str)) {
            results.push((ip, mac));
        }
    }
    results
}

#[cfg(target_os = "macos")]
fn read_arp_cache_macos(iface_name: &str) -> Vec<(Ipv4Addr, [u8; 6])> {
    let output = match std::process::Command::new("arp").arg("-an").output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::new();

    for line in stdout.lines() {
        // Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
        if !line.contains(&format!(" on {iface_name}")) {
            continue;
        }
        if !line.contains(" at ") {
            continue;
        }

        // Extract IP from between ( and )
        let ip_str = match line.split('(').nth(1).and_then(|s| s.split(')').next()) {
            Some(s) => s,
            None => continue,
        };

        // Extract MAC from after " at "
        let mac_str = match line
            .split(" at ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
        {
            Some(s) => s,
            None => continue,
        };

        // Skip incomplete entries
        if mac_str == "(incomplete)" || mac_str.starts_with('(') {
            continue;
        }

        if let (Some(ip), Some(mac)) = (parse_ipv4(ip_str), parse_mac(mac_str)) {
            results.push((ip, mac));
        }
    }
    results
}

fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    s.parse().ok()
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_lowercase_valid() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn parse_mac_uppercase_valid() {
        let mac = parse_mac("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn parse_mac_too_short() {
        assert!(parse_mac("aa:bb:cc").is_none());
    }

    #[test]
    fn parse_mac_invalid_chars() {
        assert!(parse_mac("xx:bb:cc:dd:ee:ff").is_none());
    }

    #[test]
    fn parse_ipv4_valid() {
        let ip = parse_ipv4("192.168.1.1").unwrap();
        assert_eq!(ip, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn parse_ipv4_invalid() {
        assert!(parse_ipv4("not-an-ip").is_none());
    }

    #[test]
    fn parse_ipv4_out_of_range() {
        assert!(parse_ipv4("999.999.999.999").is_none());
    }
}
