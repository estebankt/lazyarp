use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

pub type SharedState = Arc<Mutex<AppState>>;

#[derive(Debug, Clone, PartialEq)]
pub enum DeviceStatus {
    Active,
    Inactive,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum DeviceType {
    #[default]
    Unknown,
    Router,
    Phone,
    Computer,
    #[allow(dead_code)]
    Tablet,
    Printer,
    SmartTV,
    IoT,
    Nas,
    AccessPoint,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::Unknown => "Unknown",
            DeviceType::Router => "Router",
            DeviceType::Phone => "Phone",
            DeviceType::Computer => "Computer",
            DeviceType::Tablet => "Tablet",
            DeviceType::Printer => "Printer",
            DeviceType::SmartTV => "Smart TV",
            DeviceType::IoT => "IoT",
            DeviceType::Nas => "NAS",
            DeviceType::AccessPoint => "Access Point",
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            DeviceType::Unknown => "❓",
            DeviceType::Router => "🌐",
            DeviceType::Phone => "📱",
            DeviceType::Computer => "💻",
            DeviceType::Tablet => "📟",
            DeviceType::Printer => "🖨",
            DeviceType::SmartTV => "📺",
            DeviceType::IoT => "💡",
            DeviceType::Nas => "🗄",
            DeviceType::AccessPoint => "📡",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Device {
    pub ip: Ipv4Addr,
    #[allow(dead_code)]
    pub mac: [u8; 6],
    pub mac_str: String,
    pub vendor: Option<String>,
    pub status: DeviceStatus,
    #[allow(dead_code)]
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub missed_sweeps: u8,
    pub open_ports: Vec<u16>,
    pub port_scan_done: bool,
    pub hostname: Option<String>,
    pub device_type: DeviceType,
    pub mdns_services: Vec<String>,
    pub os_hint: Option<String>,
    pub http_banner: Option<String>,
}

impl Device {
    pub fn new(ip: Ipv4Addr, mac: [u8; 6], vendor: Option<String>) -> Self {
        let mac_str = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        let now = Utc::now();
        Device {
            ip,
            mac,
            mac_str,
            vendor,
            status: DeviceStatus::Active,
            first_seen: now,
            last_seen: now,
            missed_sweeps: 0,
            open_ports: Vec::new(),
            port_scan_done: false,
            hostname: None,
            device_type: DeviceType::Unknown,
            mdns_services: Vec::new(),
            os_hint: None,
            http_banner: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScanStatus {
    Idle,
    Scanning,
    Done,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub message: String,
}

pub struct AppState {
    pub devices: HashMap<[u8; 6], Device>,
    pub scan_status: ScanStatus,
    pub interface_name: String,
    pub logs: Vec<LogEntry>,
    pub selected_index: Option<usize>,
    pub filter: String,
    pub filter_mode: bool,
    pub sweep_count: u64,
    pub rescan_notify: Arc<tokio::sync::Notify>,
    pub passive_mode: bool,
}

impl AppState {
    pub fn new(
        interface_name: String,
        rescan_notify: Arc<tokio::sync::Notify>,
        passive_mode: bool,
    ) -> Self {
        AppState {
            devices: HashMap::new(),
            scan_status: ScanStatus::Idle,
            interface_name,
            logs: Vec::new(),
            selected_index: None,
            filter: String::new(),
            filter_mode: false,
            sweep_count: 0,
            rescan_notify,
            passive_mode,
        }
    }

    /// Returns devices sorted by IP, filtered by the current filter string.
    pub fn visible_devices(&self) -> Vec<&Device> {
        let filter = self.filter.to_lowercase();
        let mut devices: Vec<&Device> = self
            .devices
            .values()
            .filter(|d| {
                if filter.is_empty() {
                    return true;
                }
                d.ip.to_string().contains(&filter)
                    || d.mac_str.to_lowercase().contains(&filter)
                    || d.vendor
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&filter)
                    || d.hostname
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&filter)
                    || d.device_type.as_str().to_lowercase().contains(&filter)
            })
            .collect();
        devices.sort_by_key(|d| d.ip.octets());
        devices
    }

    pub fn push_log(&mut self, message: impl Into<String>) {
        self.logs.push(LogEntry {
            timestamp: Utc::now(),
            message: message.into(),
        });
        // Ring buffer: cap at 200 entries
        if self.logs.len() > 200 {
            self.logs.drain(0..self.logs.len() - 200);
        }
    }

    pub fn selected_device(&self) -> Option<&Device> {
        let visible = self.visible_devices();
        self.selected_index.and_then(|i| visible.get(i).copied())
    }

    #[allow(dead_code)]
    pub fn selected_mac(&self) -> Option<[u8; 6]> {
        self.selected_device().map(|d| d.mac)
    }

    pub fn clamp_selection(&mut self) {
        let len = self.visible_devices().len();
        if len == 0 {
            self.selected_index = None;
        } else {
            self.selected_index = Some(match self.selected_index {
                Some(i) => i.min(len - 1),
                None => 0,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_state() -> AppState {
        AppState::new(
            "eth0".to_string(),
            Arc::new(tokio::sync::Notify::new()),
            false,
        )
    }

    fn make_device(ip: &str, mac: [u8; 6], vendor: Option<&str>) -> Device {
        Device::new(ip.parse().unwrap(), mac, vendor.map(|s| s.to_string()))
    }

    #[test]
    fn visible_devices_empty() {
        let state = make_state();
        assert!(state.visible_devices().is_empty());
    }

    #[test]
    fn visible_devices_sorted() {
        let mut state = make_state();
        state.devices.insert(
            [0, 0, 0, 0, 0, 1],
            make_device("192.168.1.10", [0, 0, 0, 0, 0, 1], None),
        );
        state.devices.insert(
            [0, 0, 0, 0, 0, 2],
            make_device("192.168.1.2", [0, 0, 0, 0, 0, 2], None),
        );
        state.devices.insert(
            [0, 0, 0, 0, 0, 3],
            make_device("192.168.1.5", [0, 0, 0, 0, 0, 3], None),
        );

        let visible = state.visible_devices();
        assert_eq!(visible[0].ip.to_string(), "192.168.1.2");
        assert_eq!(visible[1].ip.to_string(), "192.168.1.5");
        assert_eq!(visible[2].ip.to_string(), "192.168.1.10");
    }

    #[test]
    fn filter_by_ip() {
        let mut state = make_state();
        state.devices.insert(
            [0, 0, 0, 0, 0, 1],
            make_device("192.168.1.1", [0, 0, 0, 0, 0, 1], None),
        );
        state.devices.insert(
            [0, 0, 0, 0, 0, 2],
            make_device("10.0.0.1", [0, 0, 0, 0, 0, 2], None),
        );
        state.filter = "192".to_string();

        let visible = state.visible_devices();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].ip.to_string(), "192.168.1.1");
    }

    #[test]
    fn filter_by_vendor() {
        let mut state = make_state();
        state.devices.insert(
            [0, 0, 0, 0, 0, 1],
            make_device("192.168.1.1", [0, 0, 0, 0, 0, 1], Some("Apple, Inc.")),
        );
        state.devices.insert(
            [0, 0, 0, 0, 0, 2],
            make_device("192.168.1.2", [0, 0, 0, 0, 0, 2], Some("Dell Inc.")),
        );
        state.filter = "apple".to_string();

        let visible = state.visible_devices();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].vendor.as_deref(), Some("Apple, Inc."));
    }

    #[test]
    fn filter_by_mac() {
        let mut state = make_state();
        state.devices.insert(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            make_device("192.168.1.1", [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], None),
        );
        state.devices.insert(
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            make_device("192.168.1.2", [0x11, 0x22, 0x33, 0x44, 0x55, 0x66], None),
        );
        state.filter = "aa:bb".to_string();

        let visible = state.visible_devices();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].mac_str, "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn filter_by_hostname() {
        let mut state = make_state();
        let mut d = make_device("192.168.1.1", [0, 0, 0, 0, 0, 1], None);
        d.hostname = Some("iphone-mario".to_string());
        state.devices.insert([0, 0, 0, 0, 0, 1], d);
        state.devices.insert(
            [0, 0, 0, 0, 0, 2],
            make_device("192.168.1.2", [0, 0, 0, 0, 0, 2], None),
        );
        state.filter = "iphone".to_string();

        let visible = state.visible_devices();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].hostname.as_deref(), Some("iphone-mario"));
    }

    #[test]
    fn clamp_selection_empty() {
        let mut state = make_state();
        state.selected_index = Some(5);
        state.clamp_selection();
        assert_eq!(state.selected_index, None);
    }

    #[test]
    fn clamp_selection_out_of_bounds() {
        let mut state = make_state();
        state.devices.insert(
            [0, 0, 0, 0, 0, 1],
            make_device("192.168.1.1", [0, 0, 0, 0, 0, 1], None),
        );
        state.devices.insert(
            [0, 0, 0, 0, 0, 2],
            make_device("192.168.1.2", [0, 0, 0, 0, 0, 2], None),
        );
        state.selected_index = Some(5);
        state.clamp_selection();
        assert_eq!(state.selected_index, Some(1));
    }

    #[test]
    fn push_log_ring_buffer() {
        let mut state = make_state();
        for i in 0..250 {
            state.push_log(format!("message {i}"));
        }
        assert_eq!(state.logs.len(), 200);
        // The oldest messages were drained; last message should be the most recent
        assert!(state.logs.last().unwrap().message.contains("249"));
    }
}
