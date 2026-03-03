use crate::app::{DeviceStatus, SharedState};
use crate::network::interface::{subnet_hosts, SelectedInterface};
use crate::oui::lookup::lookup_vendor;
use pnet_datalink::{self, Channel, Config, MacAddr};
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::Packet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

const SWEEP_INTERVAL_SECS: u64 = 30;
const LISTEN_DURATION_SECS: u64 = 3;
const MISSED_SWEEPS_THRESHOLD: u8 = 2;
const PASSIVE_PROBE_WAIT_SECS: u64 = 2;

#[derive(Debug, Clone, Copy)]
pub enum ScanMode {
    Active,
    Passive,
}

/// Main scanner loop — runs forever until the app exits.
pub async fn run_scanner(iface: SelectedInterface, state: SharedState, mode: ScanMode) {
    // Clone the notify handle before entering the loop
    let rescan_notify = {
        let s = state.lock().await;
        Arc::clone(&s.rescan_notify)
    };

    loop {
        match mode {
            ScanMode::Active => {
                let iface_clone = iface.clone();
                let state_clone = Arc::clone(&state);
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = arp_sweep(iface_clone, state_clone) {
                        eprintln!("ARP sweep error: {e}");
                    }
                })
                .await
                .ok();
            }
            ScanMode::Passive => {
                passive_sweep(&iface, Arc::clone(&state)).await;
            }
        }

        // Wait for either the interval or a manual rescan trigger
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(SWEEP_INTERVAL_SECS)) => {}
            _ = rescan_notify.notified() => {
                // Manual rescan requested via `r` key
            }
        }
    }
}

async fn passive_sweep(iface: &SelectedInterface, state: SharedState) {
    let hosts = subnet_hosts(iface.ip, iface.prefix_len);
    if hosts.is_empty() {
        return;
    }

    {
        let mut s = state.lock().await;
        s.scan_status = crate::app::ScanStatus::Scanning;
        s.sweep_count += 1;
        let sweep = s.sweep_count;
        s.push_log(format!(
            "Sweep #{sweep} (passive) started on {} ({} hosts)",
            iface.name,
            hosts.len()
        ));
        for device in s.devices.values_mut() {
            device.missed_sweeps += 1;
            if device.missed_sweeps >= MISSED_SWEEPS_THRESHOLD {
                device.status = DeviceStatus::Inactive;
            }
        }
    }

    udp_probe_subnet(&hosts).await;
    tokio::time::sleep(Duration::from_secs(PASSIVE_PROBE_WAIT_SECS)).await;

    let iface_name = iface.name.clone();
    let entries =
        tokio::task::spawn_blocking(move || crate::network::arp_cache::read_arp_cache(&iface_name))
            .await
            .unwrap_or_default();

    {
        let mut s = state.lock().await;
        for (src_ip, src_mac) in entries {
            let vendor = lookup_vendor(&src_mac);
            let entry = s
                .devices
                .entry(src_mac)
                .or_insert_with(|| crate::app::Device::new(src_ip, src_mac, vendor.clone()));
            entry.ip = src_ip;
            entry.status = DeviceStatus::Active;
            entry.last_seen = chrono::Utc::now();
            entry.missed_sweeps = 0;
            if entry.vendor.is_none() {
                entry.vendor = vendor;
            }
        }
        s.clamp_selection();
        s.scan_status = crate::app::ScanStatus::Done;
        let count = s.devices.len();
        s.push_log(format!("Passive sweep complete — {count} devices found"));
    }
}

async fn udp_probe_subnet(hosts: &[Ipv4Addr]) {
    if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        for host in hosts {
            let addr = SocketAddr::new(IpAddr::V4(*host), 1);
            // Fire and forget — ICMP port-unreachable responses are expected
            let _ = socket.send_to(&[0u8], addr).await;
        }
    }
}

fn arp_sweep(
    iface: SelectedInterface,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Find the pnet NetworkInterface that matches our selected interface name
    let interfaces = pnet_datalink::interfaces();
    let net_iface = interfaces
        .into_iter()
        .find(|i| i.name == iface.name)
        .ok_or("Interface not found")?;

    let config = Config {
        read_timeout: Some(Duration::from_millis(100)),
        ..Config::default()
    };
    let (mut tx, mut rx) = match pnet_datalink::channel(&net_iface, config)? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err("Unknown channel type".into()),
    };

    let hosts = subnet_hosts(iface.ip, iface.prefix_len);
    if hosts.is_empty() {
        return Ok(());
    }

    // Update scan status and increment missed_sweeps for all known devices
    {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let mut s = state.lock().await;
            s.scan_status = crate::app::ScanStatus::Scanning;
            s.sweep_count += 1;
            let sweep = s.sweep_count;
            s.push_log(format!(
                "Sweep #{sweep} started on {} ({} hosts)",
                iface.name,
                hosts.len()
            ));
            for device in s.devices.values_mut() {
                device.missed_sweeps += 1;
                if device.missed_sweeps >= MISSED_SWEEPS_THRESHOLD {
                    device.status = DeviceStatus::Inactive;
                }
            }
        });
    }

    // Send ARP requests to all hosts
    for target_ip in &hosts {
        let packet = build_arp_request(&iface, *target_ip);
        tx.send_to(&packet, None);
    }

    // Listen for replies for LISTEN_DURATION_SECS
    let deadline = std::time::Instant::now() + Duration::from_secs(LISTEN_DURATION_SECS);
    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(data) => {
                if let Some((src_ip, src_mac)) = parse_arp_reply(data, &iface) {
                    let vendor = lookup_vendor(&src_mac);
                    let rt = tokio::runtime::Handle::current();
                    rt.block_on(async {
                        let mut s = state.lock().await;
                        let entry = s.devices.entry(src_mac).or_insert_with(|| {
                            crate::app::Device::new(src_ip, src_mac, vendor.clone())
                        });
                        entry.ip = src_ip;
                        entry.status = DeviceStatus::Active;
                        entry.last_seen = chrono::Utc::now();
                        entry.missed_sweeps = 0;
                        if entry.vendor.is_none() {
                            entry.vendor = vendor;
                        }
                        // Clamp selection when new devices appear
                        s.clamp_selection();
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => break,
        }
    }

    {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let mut s = state.lock().await;
            s.scan_status = crate::app::ScanStatus::Done;
            let count = s.devices.len();
            s.push_log(format!("Sweep complete — {count} devices found"));
        });
    }

    Ok(())
}

/// Build a 42-byte ARP request packet.
fn build_arp_request(iface: &SelectedInterface, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut buf = vec![0u8; 42];

    // Ethernet header (14 bytes)
    let mut eth_packet = MutableEthernetPacket::new(&mut buf).unwrap();
    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(MacAddr::from(iface.mac));
    eth_packet.set_ethertype(EtherTypes::Arp);

    // ARP payload (28 bytes) — starts at offset 14
    let mut arp_buf = vec![0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buf).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(MacAddr::from(iface.mac));
    arp_packet.set_sender_proto_addr(iface.ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    buf[14..].copy_from_slice(arp_packet.packet());
    buf
}

/// Parse an ARP reply from a raw Ethernet frame, returning (src_ip, src_mac) if valid.
fn parse_arp_reply(data: &[u8], iface: &SelectedInterface) -> Option<(Ipv4Addr, [u8; 6])> {
    let eth = EthernetPacket::new(data)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    // Ignore our own packets
    let sender_mac = arp.get_sender_hw_addr().octets();
    if sender_mac == iface.mac {
        return None;
    }
    let sender_ip = arp.get_sender_proto_addr();
    Some((sender_ip, sender_mac))
}
