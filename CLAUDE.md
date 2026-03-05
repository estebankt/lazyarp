# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`lazyarp` is a Rust TUI application that performs ARP-based network scanning with device fingerprinting. It discovers devices on the local subnet, identifies manufacturers via IEEE OUI lookup, classifies device types via mDNS/SSDP/port inference, and scans open ports on selected devices.

## Build Requirements

**libpcap** must be installed (Arch: `sudo pacman -S libpcap`).

**OUI database** must be downloaded before first build (embedded at compile time):
```bash
curl -L -o assets/oui.csv https://standards-oui.ieee.org/oui/oui.csv
```

## Common Commands

```bash
# Build
cargo build
cargo build --release

# Run (active mode requires raw socket access)
sudo ./target/release/lazyarp
# Or grant capability to avoid sudo:
sudo setcap cap_net_raw+eip ./target/release/lazyarp

# Run without privileges (passive mode, auto-detected)
./target/release/lazyarp

# Test
cargo test

# Run a single test
cargo test test_vmware_lookup
```

## Architecture

The app has four concurrent tasks sharing `SharedState = Arc<Mutex<AppState>>`:

1. **Scanner task** (`network/scanner.rs`) — runs forever, sweeps every 30 s or on manual trigger (`r` key via `Notify`). Two modes:
   - **Active** (`ScanMode::Active`): sends raw ARP requests via `pnet`, listens for replies. Requires `cap_net_raw` or root. Runs in `spawn_blocking` since `pnet` is synchronous.
   - **Passive** (`ScanMode::Passive`): sends UDP datagrams to each host to provoke ARP activity, then reads the kernel ARP cache (`/proc/net/arp` on Linux, `arp -an` on macOS). No elevated privileges needed.

2. **mDNS listener** (`network/mdns.rs`) — joins multicast `224.0.0.251:5353`, parses DNS-SD PTR records via `dns-parser`. Extracts hostnames and classifies device types from service strings (`_ssh._tcp` → Computer, `_airplay._tcp` → SmartTV, `_googlecast._tcp` → SmartTV/ChromecastOS, `_companion-link._tcp` → Phone/iOS, etc.).

3. **SSDP listener** (`network/ssdp.rs`) — joins multicast `239.255.255.250:1900`, issues an M-SEARCH probe on startup, and listens for NOTIFY announcements. Parses `SERVER:` and `NT:` headers to infer device type (Roku/Chromecast → SmartTV, Synology/QNAP → NAS, OpenWrt/DD-WRT → Router, etc.).

4. **TUI task** (`tui.rs`) — crossterm event loop rendering at ~60 fps via `try_lock`. Key events dispatch `EventAction` variants; port scans, HTTP banner grabs, and clipboard writes spawn their own tasks.

### Key Files

| File | Role |
|------|------|
| `main.rs` | Startup: interface selection → permission check → spawn scanner + mDNS + SSDP + TUI |
| `app.rs` | `AppState` + `Device` + `DeviceType` types; all shared mutable state |
| `tui.rs` | Event loop, keybindings, `EventAction` dispatch, `copy_to_clipboard` helper |
| `network/scanner.rs` | Active ARP sweep and passive UDP-probe sweep |
| `network/mdns.rs` | Passive mDNS listener; `classify_mdns_service` → `DeviceType` |
| `network/ssdp.rs` | Passive SSDP listener + M-SEARCH probe; `server_to_type` / `nt_to_type` |
| `network/interface.rs` | Interface selection (`select_interface`), `subnet_hosts`, `check_permissions` |
| `network/arp_cache.rs` | Read kernel ARP table (Linux `/proc/net/arp` + macOS `arp -an`) |
| `network/port_scanner.rs` | TCP connect scan on 19 common ports (500 ms timeout); `infer_device_type`, `infer_os_hint`, `grab_http_banner` |
| `oui/lookup.rs` | IEEE OUI CSV embedded via `include_bytes!`, lazily parsed into a `HashMap`; `vendor_device_hint` |
| `ui/app_ui.rs` | Root layout (35% list / 65% details / 3-line log pane) |
| `ui/device_list.rs` | List with emoji type tags, hostname preference over vendor |
| `ui/device_details.rs` | Details panel: IP, MAC, vendor, hostname, device type, OS, mDNS services, HTTP banner, open ports |

### State Flow

- Devices are keyed by MAC address in `AppState::devices: HashMap<[u8; 6], Device>`.
- Each sweep increments `missed_sweeps` on all devices; devices not seen for 2 sweeps become `Inactive` (marked `○`) rather than removed.
- Device type is inferred in priority order: OUI vendor hint (weakest) → port scan → mDNS (always overwrites) → SSDP (only if Unknown).
- Port scans are triggered automatically when navigating to a device (`j`/`k`) and cached in `device.port_scan_done`. `Enter` forces a re-scan.
- The filter (`/`) applies to IP, MAC, vendor, hostname, and device type strings; `visible_devices()` returns a sorted, filtered slice used by both the UI and selection logic.
- The `y` key yanks the selected IP via `copy_to_clipboard` which shells out to `wl-copy` (Wayland), `xclip`/`xsel` (X11), `pbcopy` (macOS), or `clip` (Windows) — the subprocess stays alive to hold Wayland clipboard ownership after the app exits.

### DeviceType Enum (`app.rs`)

`Unknown, Router, Phone, Computer, Tablet, Printer, SmartTV, IoT, Nas, AccessPoint`

- `tag()` → emoji: ❓🌐📱💻📟🖨📺💡🗄📡
- `as_str()` → human-readable label

### Dependencies

| Crate | Purpose |
|-------|---------|
| `ratatui` | TUI rendering |
| `crossterm` | Terminal I/O |
| `pnet` / `pnet_datalink` / `pnet_packet` | Raw ARP packets (active mode) |
| `tokio` | Async runtime |
| `dns-parser` | DNS packet parser for mDNS PTR records (`RData::PTR`) |
| `socket2` | UDP socket with `SO_REUSEADDR` for mDNS/SSDP multicast |
| `ipnetwork` | Subnet iteration |
| `chrono` | Timestamps |
| `csv` + `once_cell` | OUI database parsing and lazy init |
| `anyhow` / `thiserror` | Error handling |

### Known Gotchas

- `dns-parser = "0.8"` uses `RData::PTR` (uppercase variant), not `Ptr`.
- `socket2 v0.5` does not expose `set_reuse_port` — only use `set_reuse_address`.
- If `avahi-daemon` holds port 5353, mDNS bind fails gracefully (logged, task returns).
- `COMMON_PORTS` must stay sorted ascending by port number (enforced by `common_ports_sorted` test).
- `wl-copy` must **not** be waited on after writing stdin — it daemonizes to hold Wayland clipboard ownership.
