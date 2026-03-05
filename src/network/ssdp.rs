use crate::app::{DeviceType, SharedState};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

const SSDP_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;

const MSEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 3\r\n\
ST: ssdp:all\r\n\
\r\n";

/// Infer device type from an SSDP SERVER: header value.
fn server_to_type(server: &str) -> Option<(DeviceType, Option<String>)> {
    let s = server.to_lowercase();
    if s.contains("roku") {
        return Some((DeviceType::SmartTV, Some("Roku OS".to_string())));
    }
    if s.contains("chromecast") || (s.contains("google") && s.contains("cast")) {
        return Some((DeviceType::SmartTV, Some("ChromecastOS".to_string())));
    }
    if (s.contains("samsung") || s.contains("lg") || s.contains("sony")) && s.contains("tv") {
        return Some((DeviceType::SmartTV, None));
    }
    if s.contains("synology") {
        return Some((DeviceType::Nas, None));
    }
    if s.contains("qnap") {
        return Some((DeviceType::Nas, None));
    }
    if s.contains("openwrt") || s.contains("dd-wrt") {
        return Some((DeviceType::Router, None));
    }
    if s.contains("printer") || s.contains("canon") || s.contains(" hp ") || s.contains("/hp") {
        return Some((DeviceType::Printer, None));
    }
    None
}

/// Infer device type from an SSDP NT: (notification type) header value.
fn nt_to_type(nt: &str) -> Option<DeviceType> {
    let s = nt.to_lowercase();
    if s.contains("mediarenderer") || s.contains("mediaplayer") {
        return Some(DeviceType::SmartTV);
    }
    if s.contains(":printer:") {
        return Some(DeviceType::Printer);
    }
    if s.contains("internetgatewaydevice") || s.contains(":router:") {
        return Some(DeviceType::Router);
    }
    None
}

/// Parse SERVER and NT header values from a raw SSDP message.
fn parse_ssdp_headers(data: &str) -> (Option<String>, Option<String>) {
    let mut server = None;
    let mut nt = None;
    for line in data.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("server:") && server.is_none() {
            server = Some(line[7..].trim().to_string());
        } else if lower.starts_with("nt:") && nt.is_none() {
            nt = Some(line[3..].trim().to_string());
        }
    }
    (server, nt)
}

/// Background task: listens for SSDP announcements and responds to M-SEARCH
/// to identify smart TVs, NAS devices, routers, and printers.
pub async fn run_ssdp_listener(state: SharedState) {
    let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(s) => s,
        Err(e) => {
            state
                .lock()
                .await
                .push_log(format!("SSDP: socket creation failed: {e}"));
            return;
        }
    };

    let _ = socket.set_reuse_address(true);

    let bind_addr: SocketAddr = format!("0.0.0.0:{SSDP_PORT}").parse().unwrap();
    if let Err(e) = socket.bind(&bind_addr.into()) {
        state
            .lock()
            .await
            .push_log(format!("SSDP: bind failed (port {SSDP_PORT}): {e}"));
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
                .push_log(format!("SSDP: tokio socket failed: {e}"));
            return;
        }
    };

    if let Err(e) = udp.join_multicast_v4(SSDP_MULTICAST_ADDR, Ipv4Addr::UNSPECIFIED) {
        state
            .lock()
            .await
            .push_log(format!("SSDP: multicast join failed: {e}"));
        return;
    }

    state
        .lock()
        .await
        .push_log("SSDP listener started".to_string());

    let msearch_target: SocketAddr = format!("{SSDP_MULTICAST_ADDR}:{SSDP_PORT}")
        .parse()
        .unwrap();

    // Send initial M-SEARCH to discover existing devices
    let _ = udp.send_to(MSEARCH, msearch_target).await;

    // Subsequent M-SEARCHes every 60 seconds (first tick delayed by 60s)
    let mut msearch_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(60),
        tokio::time::Duration::from_secs(60),
    );

    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            _ = msearch_interval.tick() => {
                let _ = udp.send_to(MSEARCH, msearch_target).await;
            }
            result = udp.recv_from(&mut buf) => {
                let (len, peer) = match result {
                    Ok(x) => x,
                    Err(_) => continue,
                };

                let src_ip = match peer.ip() {
                    std::net::IpAddr::V4(ip) => ip,
                    _ => continue,
                };

                let data = match std::str::from_utf8(&buf[..len]) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                // Only process NOTIFY alive messages and HTTP 200 OK responses
                let is_notify = data.starts_with("NOTIFY") && data.contains("ssdp:alive");
                let is_response = data.starts_with("HTTP/1.1 200") || data.starts_with("HTTP/1.0 200");
                if !is_notify && !is_response {
                    continue;
                }

                let (server, nt) = parse_ssdp_headers(data);

                let mut device_type: Option<DeviceType> = None;
                let mut os_hint: Option<String> = None;

                if let Some(ref s) = server {
                    if let Some((dt, oh)) = server_to_type(s) {
                        device_type = Some(dt);
                        os_hint = oh;
                    }
                }
                if device_type.is_none() {
                    if let Some(ref n) = nt {
                        device_type = nt_to_type(n);
                    }
                }

                if device_type.is_none() && server.is_none() {
                    continue;
                }

                let mut s = state.lock().await;
                if let Some(device) = s.devices.values_mut().find(|d| d.ip == src_ip) {
                    if let Some(dt) = device_type {
                        if device.device_type == DeviceType::Unknown {
                            device.device_type = dt;
                        }
                    }
                    if device.os_hint.is_none() {
                        device.os_hint = os_hint;
                    }
                    // Store SERVER header as a banner signal if we don't have one yet
                    if device.http_banner.is_none() {
                        device.http_banner = server;
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
    fn server_roku() {
        let (dt, os) = server_to_type("Roku/9.2 UPnP/1.0 Roku/9.2").unwrap();
        assert_eq!(dt, DeviceType::SmartTV);
        assert_eq!(os, Some("Roku OS".to_string()));
    }

    #[test]
    fn server_synology() {
        let (dt, _) = server_to_type("Synology DiskStation").unwrap();
        assert_eq!(dt, DeviceType::Nas);
    }

    #[test]
    fn server_openwrt() {
        let (dt, _) = server_to_type("OpenWrt/21.02 UPnP/1.1 MiniUPnPd/2.2.1").unwrap();
        assert_eq!(dt, DeviceType::Router);
    }

    #[test]
    fn nt_mediarenderer() {
        assert_eq!(
            nt_to_type("urn:schemas-upnp-org:device:MediaRenderer:1"),
            Some(DeviceType::SmartTV)
        );
    }

    #[test]
    fn nt_gateway() {
        assert_eq!(
            nt_to_type("urn:schemas-upnp-org:device:InternetGatewayDevice:1"),
            Some(DeviceType::Router)
        );
    }

    #[test]
    fn parse_headers_notify() {
        let msg = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nSERVER: Synology DiskStation\r\nNT: urn:schemas-upnp-org:device:Basic:1\r\n\r\n";
        let (server, nt) = parse_ssdp_headers(msg);
        assert_eq!(server.as_deref(), Some("Synology DiskStation"));
        assert_eq!(nt.as_deref(), Some("urn:schemas-upnp-org:device:Basic:1"));
    }
}
