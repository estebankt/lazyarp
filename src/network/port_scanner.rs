use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// Common ports to check with their service names.
pub const COMMON_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (3389, "RDP"),
    (5900, "VNC"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
];

const CONNECT_TIMEOUT_MS: u64 = 500;

/// Scan the common ports on the given IP address concurrently.
/// Returns a sorted list of open port numbers.
pub async fn scan_ports(ip: Ipv4Addr) -> Vec<u16> {
    let mut handles = Vec::new();

    for &(port, _) in COMMON_PORTS {
        let handle = tokio::spawn(async move {
            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            let timeout = Duration::from_millis(CONNECT_TIMEOUT_MS);

            // Use blocking TCP connect in a blocking thread to avoid runtime blocking
            let open = tokio::task::spawn_blocking(move || {
                TcpStream::connect_timeout(&addr, timeout).is_ok()
            })
            .await
            .unwrap_or(false);

            if open {
                Some(port)
            } else {
                None
            }
        });
        handles.push(handle);
    }

    let mut open_ports = Vec::new();
    for h in handles {
        if let Ok(Some(port)) = h.await {
            open_ports.push(port);
        }
    }
    open_ports.sort();
    open_ports
}

/// Return the service name for a well-known port.
pub fn port_service(port: u16) -> &'static str {
    COMMON_PORTS
        .iter()
        .find(|&&(p, _)| p == port)
        .map(|&(_, s)| s)
        .unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ports() {
        assert_eq!(port_service(22), "SSH");
        assert_eq!(port_service(80), "HTTP");
        assert_eq!(port_service(443), "HTTPS");
        assert_eq!(port_service(21), "FTP");
    }

    #[test]
    fn unknown_port() {
        assert_eq!(port_service(9999), "?");
    }

    #[test]
    fn common_ports_sorted() {
        let ports: Vec<u16> = COMMON_PORTS.iter().map(|&(p, _)| p).collect();
        let mut sorted = ports.clone();
        sorted.sort();
        assert_eq!(ports, sorted);
    }
}
