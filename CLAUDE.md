# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`lazyarp` is a Rust TUI application that performs ARP-based network scanning. It discovers devices on the local subnet, identifies manufacturers via IEEE OUI lookup, and scans open ports on selected devices.

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

# Run (requires raw socket access)
sudo ./target/release/lazyarp
# Or grant capability to avoid sudo:
sudo setcap cap_net_raw+eip ./target/release/lazyarp

# Test
cargo test

# Run a single test
cargo test test_vmware_lookup
```

## Architecture

The app has two concurrent tasks sharing `SharedState = Arc<Mutex<AppState>>`:

1. **Scanner task** (`network/scanner.rs`) — runs forever, sweeps every 30s or on manual trigger (`r` key via `Notify`). Two modes:
   - **Active** (`ScanMode::Active`): sends raw ARP requests via `pnet`, listens for replies. Requires `cap_net_raw` or root. Runs in `spawn_blocking` since `pnet` is synchronous.
   - **Passive** (`ScanMode::Passive`): sends UDP datagrams to each host to provoke ARP activity, then reads the kernel ARP cache (`/proc/net/arp` on Linux, `arp -an` on macOS). No elevated privileges needed.

2. **TUI task** (`tui.rs`) — crossterm event loop rendering at ~60fps via `try_lock`. Key events dispatch `EventAction` variants; port scans and clipboard writes spawn their own tasks.

### Key Files

| File | Role |
|------|------|
| `main.rs` | Startup: interface selection → permission check → spawn scanner + TUI |
| `app.rs` | `AppState` + `Device` types; all shared mutable state |
| `tui.rs` | Event loop, keybindings, `EventAction` dispatch |
| `network/scanner.rs` | Active ARP sweep and passive UDP-probe sweep |
| `network/interface.rs` | Interface selection (`select_interface`), `subnet_hosts` |
| `network/arp_cache.rs` | Read kernel ARP table (Linux + macOS) |
| `network/port_scanner.rs` | TCP connect scan on 9 common ports (500ms timeout) |
| `oui/lookup.rs` | IEEE OUI CSV embedded via `include_bytes!`, lazily parsed into a `HashMap` |
| `ui/app_ui.rs` | Root layout (35% list / 65% details / 3-line log pane) |

### State Flow

- Devices are keyed by MAC address in `AppState::devices: HashMap<[u8; 6], Device>`.
- Each sweep increments `missed_sweeps` on all devices; devices not seen for 2 sweeps become `Inactive` (marked `○`) rather than removed.
- Port scans are triggered automatically when navigating to a device (`j`/`k`) and cached in `device.port_scan_done`.
- The filter (`/`) applies to IP, MAC, and vendor strings; `visible_devices()` returns a sorted, filtered slice used by both the UI and selection logic.
