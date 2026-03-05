use crate::app::{DeviceType, SharedState};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

const MDNS_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// Map a mDNS service type string to (DeviceType, optional OS hint).
fn classify_mdns_service(service: &str) -> Option<(DeviceType, Option<&'static str>)> {
    let s = service.to_lowercase();
    if s.contains("_companion-link._tcp") || s.contains("_apple-mobsubt._tcp") {
        return Some((DeviceType::Phone, Some("iOS")));
    }
    if s.contains("_appletv._tcp") {
        return Some((DeviceType::SmartTV, Some("tvOS")));
    }
    if s.contains("_airplay._tcp") || s.contains("_raop._tcp") {
        return Some((DeviceType::SmartTV, None));
    }
    if s.contains("_airport._tcp") {
        return Some((DeviceType::AccessPoint, None));
    }
    if s.contains("_googlecast._tcp") {
        return Some((DeviceType::SmartTV, Some("ChromecastOS")));
    }
    if s.contains("_androidtvremote2._tcp") {
        return Some((DeviceType::SmartTV, Some("Android TV")));
    }
    if s.contains("_spotify-connect._tcp") {
        return Some((DeviceType::IoT, None));
    }
    if s.contains("_printer._tcp") || s.contains("_ipp._tcp") {
        return Some((DeviceType::Printer, None));
    }
    if s.contains("_smb._tcp") {
        return Some((DeviceType::Computer, Some("Windows/Samba")));
    }
    if s.contains("_ssh._tcp") {
        return Some((DeviceType::Computer, None));
    }
    if s.contains("_afpovertcp._tcp") {
        return Some((DeviceType::Computer, Some("macOS")));
    }
    if s.contains("_workstation._tcp") {
        return Some((DeviceType::Computer, None));
    }
    None
}

/// Background task: listens for mDNS announcements on the local network and
/// updates device hostname, type, and OS hint in shared state.
pub async fn run_mdns_listener(state: SharedState, iface_ip: Ipv4Addr) {
    let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(s) => s,
        Err(e) => {
            state
                .lock()
                .await
                .push_log(format!("mDNS: socket creation failed: {e}"));
            return;
        }
    };

    let _ = socket.set_reuse_address(true);

    let bind_addr: SocketAddr = format!("0.0.0.0:{MDNS_PORT}").parse().unwrap();
    if let Err(e) = socket.bind(&bind_addr.into()) {
        state
            .lock()
            .await
            .push_log(format!("mDNS: bind failed (port {MDNS_PORT}): {e}"));
        return;
    }

    let std_socket: std::net::UdpSocket = socket.into();
    if std_socket.set_nonblocking(true).is_err() {
        return;
    }

    let udp = match UdpSocket::from_std(std_socket) {
        Ok(s) => s,
        Err(e) => {
            state
                .lock()
                .await
                .push_log(format!("mDNS: tokio socket failed: {e}"));
            return;
        }
    };

    if let Err(e) = udp.join_multicast_v4(MDNS_MULTICAST_ADDR, iface_ip) {
        state
            .lock()
            .await
            .push_log(format!("mDNS: multicast join failed: {e}"));
        return;
    }

    state
        .lock()
        .await
        .push_log("mDNS listener started".to_string());

    let mut buf = [0u8; 4096];
    loop {
        let (len, peer) = match udp.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => continue,
        };

        let src_ip = match peer.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => continue,
        };

        let data = &buf[..len];
        let packet = match dns_parser::Packet::parse(data) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let mut hostname: Option<String> = None;
        let mut services: Vec<String> = Vec::new();

        for answer in packet.answers.iter().chain(packet.additional.iter()) {
            match &answer.data {
                dns_parser::RData::A(record) => {
                    // A record name is the device hostname (e.g. "iPhone-Mario.local")
                    if record.0 == src_ip {
                        let name = answer.name.to_string();
                        if let Some(stripped) = name
                            .strip_suffix(".local.")
                            .or_else(|| name.strip_suffix(".local"))
                        {
                            if hostname.is_none() {
                                hostname = Some(stripped.to_string());
                            }
                        }
                    }
                }
                dns_parser::RData::PTR(_) => {
                    // PTR record name is the service type (e.g. "_companion-link._tcp.local")
                    let service = answer.name.to_string();
                    if service.starts_with('_') {
                        services.push(service);
                    }
                }
                _ => {}
            }
        }

        if hostname.is_none() && services.is_empty() {
            continue;
        }

        let mut s = state.lock().await;
        if let Some(device) = s.devices.values_mut().find(|d| d.ip == src_ip) {
            if hostname.is_some() && device.hostname.is_none() {
                device.hostname = hostname;
            }
            for svc in &services {
                if !device.mdns_services.contains(svc) {
                    device.mdns_services.push(svc.clone());
                }
                if let Some((dtype, os)) = classify_mdns_service(svc) {
                    device.device_type = dtype;
                    if device.os_hint.is_none() {
                        if let Some(os_str) = os {
                            device.os_hint = Some(os_str.to_string());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_ios_companion() {
        let result = classify_mdns_service("_companion-link._tcp.local");
        assert_eq!(result, Some((DeviceType::Phone, Some("iOS"))));
    }

    #[test]
    fn classify_appletv() {
        let result = classify_mdns_service("_appletv._tcp.local");
        assert_eq!(result, Some((DeviceType::SmartTV, Some("tvOS"))));
    }

    #[test]
    fn classify_chromecast() {
        let result = classify_mdns_service("_googlecast._tcp.local");
        assert_eq!(result, Some((DeviceType::SmartTV, Some("ChromecastOS"))));
    }

    #[test]
    fn classify_ssh_computer() {
        let (dtype, _) = classify_mdns_service("_ssh._tcp.local").unwrap();
        assert_eq!(dtype, DeviceType::Computer);
    }

    #[test]
    fn classify_unknown_service() {
        assert_eq!(classify_mdns_service("_http._tcp.local"), None);
    }
}
