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

#[derive(Debug, Clone)]
pub struct Device {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub mac_str: String,
    pub vendor: Option<String>,
    pub status: DeviceStatus,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub missed_sweeps: u8,
    pub open_ports: Vec<u16>,
    pub port_scan_done: bool,
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
    pub fn new(interface_name: String, rescan_notify: Arc<tokio::sync::Notify>, passive_mode: bool) -> Self {
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
