use crate::error::LazyarpError;
use pnet_datalink::{self, NetworkInterface};
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct SelectedInterface {
    pub name: String,
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
}

/// Pick the best non-loopback, non-virtual interface that has an IPv4 address.
pub fn select_interface() -> Result<SelectedInterface, LazyarpError> {
    let interfaces = pnet_datalink::interfaces();

    for iface in &interfaces {
        // Skip loopback, down interfaces, virtual/tunnel interfaces
        if iface.is_loopback() || !iface.is_up() {
            continue;
        }
        if is_virtual_interface(&iface.name) {
            continue;
        }

        // Needs a valid MAC
        let mac_bytes = match &iface.mac {
            Some(m) if !m.is_zero() => m.octets(),
            _ => continue,
        };

        // Needs an IPv4 address
        for ip_net in &iface.ips {
            if let std::net::IpAddr::V4(ipv4) = ip_net.ip() {
                if ipv4.is_loopback() || ipv4.is_unspecified() {
                    continue;
                }
                let prefix_len = match ip_net {
                    ipnetwork::IpNetwork::V4(net) => net.prefix(),
                    _ => continue,
                };
                return Ok(SelectedInterface {
                    name: iface.name.clone(),
                    mac: mac_bytes,
                    ip: ipv4,
                    prefix_len,
                });
            }
        }
    }

    Err(LazyarpError::NoSuitableInterface)
}

fn is_virtual_interface(name: &str) -> bool {
    // Filter out macOS virtual/tunnel interfaces
    let prefixes = [
        "utun", "awdl", "llw", "bridge", "vmnet", "veth", "docker", "lo",
    ];
    prefixes.iter().any(|p| name.starts_with(p))
}

/// Check if we can open a raw socket (requires root or cap_net_raw).
pub fn check_permissions(iface: &NetworkInterface) -> Result<(), LazyarpError> {
    use pnet_datalink::channel;
    use pnet_datalink::ChannelType;
    use pnet_datalink::Config;

    let config = Config {
        channel_type: ChannelType::Layer2,
        ..Config::default()
    };

    match channel(iface, config) {
        Ok(_) => Ok(()),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
            ) =>
        {
            Err(LazyarpError::InsufficientPermissions)
        }
        Err(e) => Err(LazyarpError::Network(e)),
    }
}

/// Enumerate all IPs in a /prefix subnet (excluding network + broadcast).
pub fn subnet_hosts(base_ip: Ipv4Addr, prefix_len: u8) -> Vec<Ipv4Addr> {
    let base = u32::from(base_ip);
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    let network = base & mask;
    let broadcast = network | !mask;

    // Skip overly large subnets (> /16 = 65534 hosts) for safety
    let host_count = broadcast - network - 1;
    if host_count > 65534 {
        return Vec::new();
    }

    (network + 1..broadcast).map(Ipv4Addr::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_hosts_slash24() {
        let hosts = subnet_hosts("192.168.1.0".parse().unwrap(), 24);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], "192.168.1.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(hosts[253], "192.168.1.254".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn subnet_hosts_slash30() {
        let hosts = subnet_hosts("10.0.0.0".parse().unwrap(), 30);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0], "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(hosts[1], "10.0.0.2".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn subnet_hosts_slash16_boundary() {
        let hosts = subnet_hosts("10.0.0.0".parse().unwrap(), 16);
        assert_eq!(hosts.len(), 65534);
    }

    #[test]
    fn subnet_hosts_too_large() {
        // /15 = 131070 hosts, exceeds limit
        let hosts = subnet_hosts("10.0.0.0".parse().unwrap(), 15);
        assert!(hosts.is_empty());
    }

    #[test]
    fn is_virtual_docker() {
        assert!(is_virtual_interface("docker0"));
    }

    #[test]
    fn is_virtual_veth() {
        assert!(is_virtual_interface("veth0abc"));
    }

    #[test]
    fn not_virtual_eth0() {
        assert!(!is_virtual_interface("eth0"));
    }

    #[test]
    fn not_virtual_wlan0() {
        assert!(!is_virtual_interface("wlan0"));
    }
}
