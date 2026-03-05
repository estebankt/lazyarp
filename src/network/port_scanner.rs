use crate::app::DeviceType;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Common ports to check with their service names.
pub const COMMON_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (80, "HTTP"),
    (137, "NetBIOS"),
    (443, "HTTPS"),
    (445, "SMB"),
    (548, "AFP"),
    (631, "IPP"),
    (1883, "MQTT"),
    (3389, "RDP"),
    (5000, "UPnP"),
    (5900, "VNC"),
    (7000, "AirPlay"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (9100, "RAW-Print"),
    (49152, "lockdownd"),
    (62078, "lockdownd-legacy"),
];

const CONNECT_TIMEOUT_MS: u64 = 500;

/// Scan the common ports on the given IP address concurrently.
/// Returns a sorted list of open port numbers.
pub async fn scan_ports(ip: Ipv4Addr) -> Vec<u16> {
    let mut handles = Vec::new();

    for &(port, _) in COMMON_PORTS {
        let handle = tokio::spawn(async move {
            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            let connect_timeout = Duration::from_millis(CONNECT_TIMEOUT_MS);

            // Use blocking TCP connect in a blocking thread to avoid runtime blocking
            let open = tokio::task::spawn_blocking(move || {
                TcpStream::connect_timeout(&addr, connect_timeout).is_ok()
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

/// Infer device type from open ports.
/// Checks in priority order; falls back to vendor_hint if no ports match.
pub fn infer_device_type(open_ports: &[u16], vendor_hint: Option<DeviceType>) -> DeviceType {
    // iOS lockdownd — near-certain iPhone/iPad
    if open_ports.contains(&62078) || open_ports.contains(&49152) {
        return DeviceType::Phone;
    }
    // AFP without SMB → macOS (SMB would be present on Windows)
    if open_ports.contains(&548) && !open_ports.contains(&445) {
        return DeviceType::Computer;
    }
    // SMB → Windows or Samba (Mac/Linux)
    if open_ports.contains(&445) {
        return DeviceType::Computer;
    }
    // Printer protocols
    if open_ports.contains(&9100) || open_ports.contains(&631) {
        return DeviceType::Printer;
    }
    // AirPlay → Apple TV, HomePod, etc.
    if open_ports.contains(&7000) {
        return DeviceType::SmartTV;
    }
    // MQTT broker → IoT hub/device
    if open_ports.contains(&1883) {
        return DeviceType::IoT;
    }
    // Fall back to vendor hint
    vendor_hint.unwrap_or(DeviceType::Unknown)
}

/// Infer OS from open ports and optional vendor string.
pub fn infer_os_hint(open_ports: &[u16], vendor: Option<&str>) -> Option<String> {
    let vendor_lower = vendor.unwrap_or("").to_lowercase();

    if open_ports.contains(&62078) || open_ports.contains(&49152) {
        return Some("iOS".to_string());
    }
    if open_ports.contains(&548) && vendor_lower.contains("apple") {
        return Some("macOS".to_string());
    }
    if open_ports.contains(&445) && vendor_lower.contains("apple") {
        return Some("macOS".to_string());
    }
    if open_ports.contains(&445) && !vendor_lower.contains("apple") {
        return Some("Windows".to_string());
    }
    if open_ports.contains(&22) && vendor_lower.contains("raspberry pi") {
        return Some("Linux".to_string());
    }
    None
}

/// Attempt an HTTP GET on the given port and return the Server: header value.
pub async fn grab_http_banner(ip: Ipv4Addr, port: u16) -> Option<String> {
    let addr = format!("{ip}:{port}");
    let mut stream = timeout(
        Duration::from_millis(500),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .ok()?
    .ok()?;

    let request = format!("GET / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n");
    timeout(
        Duration::from_millis(500),
        stream.write_all(request.as_bytes()),
    )
    .await
    .ok()?
    .ok()?;

    let mut buf = vec![0u8; 1024];
    let n = timeout(Duration::from_millis(1000), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    let response = std::str::from_utf8(&buf[..n]).ok()?;
    for line in response.lines() {
        if line.to_lowercase().starts_with("server:") {
            return Some(line[7..].trim().to_string());
        }
    }
    None
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

    #[test]
    fn infer_ios_from_lockdownd() {
        assert_eq!(infer_device_type(&[62078], None), DeviceType::Phone);
        assert_eq!(infer_device_type(&[49152], None), DeviceType::Phone);
    }

    #[test]
    fn infer_macos_from_afp() {
        assert_eq!(infer_device_type(&[548, 22], None), DeviceType::Computer);
    }

    #[test]
    fn infer_computer_from_smb() {
        assert_eq!(infer_device_type(&[445, 80], None), DeviceType::Computer);
    }

    #[test]
    fn infer_printer() {
        assert_eq!(infer_device_type(&[9100], None), DeviceType::Printer);
        assert_eq!(infer_device_type(&[631], None), DeviceType::Printer);
    }

    #[test]
    fn infer_smarttv_from_airplay() {
        assert_eq!(infer_device_type(&[7000], None), DeviceType::SmartTV);
    }

    #[test]
    fn infer_vendor_fallback() {
        assert_eq!(
            infer_device_type(&[80], Some(DeviceType::Router)),
            DeviceType::Router
        );
    }

    #[test]
    fn infer_unknown_no_hint() {
        assert_eq!(infer_device_type(&[80, 443], None), DeviceType::Unknown);
    }

    #[test]
    fn os_hint_ios() {
        assert_eq!(infer_os_hint(&[62078], None), Some("iOS".to_string()));
        assert_eq!(infer_os_hint(&[49152], None), Some("iOS".to_string()));
    }

    #[test]
    fn os_hint_macos_afp() {
        assert_eq!(
            infer_os_hint(&[548], Some("Apple, Inc.")),
            Some("macOS".to_string())
        );
    }

    #[test]
    fn os_hint_windows_smb() {
        assert_eq!(
            infer_os_hint(&[445], Some("Dell Inc.")),
            Some("Windows".to_string())
        );
    }

    #[test]
    fn os_hint_none() {
        assert_eq!(infer_os_hint(&[80, 443], None), None);
    }
}
