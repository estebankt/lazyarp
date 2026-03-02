# lazyarp

ARP-based network scanner with a terminal UI. Think Fing, but keyboard-driven and fast.

```
┌ Devices (4) ──────────────┬ Device Details ───────────────────────────────┐
│ > ● 192.168.1.1   Router  │   IP Address : 192.168.1.42                   │
│   ● 192.168.1.42  Apple   │   MAC Address: A4:C3:F0:12:34:56              │
│   ● 192.168.1.55          │   Vendor     : Apple, Inc.                    │
│   ○ 192.168.1.88  Samsung │   Status     : ● Active                       │
│                           │   Last Seen  : 01:14:32 UTC                   │
│                           │                                                │
│                           │   Open Ports                                   │
│                           │      22  SSH                                   │
│                           │      80  HTTP                                  │
└───────────────────────────┴────────────────────────────────────────────────┘
┌ lazyarp [DONE]  iface: en0 ────────────────────────────────────────────────┐
│ [01:14:35] Sweep complete — 4 devices found                                │
└────────────────────────────────────────────────────────────────────────────┘
```

## Requirements

Raw socket access — needs `sudo` on macOS, or `cap_net_raw` on Linux.

libpcap must be installed:
- macOS: ships with Xcode tools, no action needed
- Ubuntu/Debian: `apt install libpcap-dev`
- Fedora/RHEL: `dnf install libpcap-devel`

## Build

```bash
# download OUI database (one-time, ~3.5MB)
curl -L -o assets/oui.csv https://standards-oui.ieee.org/oui/oui.csv

cargo build --release
```

## Run

```bash
# macOS
sudo ./target/release/lazyarp

# Linux (option 1: sudo)
sudo ./target/release/lazyarp

# Linux (option 2: grant capability so you don't need sudo every time)
sudo setcap cap_net_raw+eip ./target/release/lazyarp
./target/release/lazyarp
```

## Keys

| key | action |
|-----|--------|
| `j` / `k` | navigate up/down |
| `y` | yank selected IP to clipboard |
| `/` | filter devices |
| `Esc` | clear filter |
| `r` | rescan now |
| `q` | quit |

Selecting a device automatically scans it for open ports (22, 80, 443, and a few others). Devices that stop responding are marked inactive (`○`) rather than removed.

## How it works

Sends ARP requests across the local subnet every 30 seconds and listens for replies. MAC prefixes are matched against the embedded IEEE OUI table to identify manufacturers. Port scanning runs concurrently with a 500ms connect timeout per port.

## Caveats

- Only scans the local subnet of whichever interface gets picked automatically
- Subnets larger than /16 are skipped (too many hosts)
- Port scan only checks 9 common ports, not a full nmap sweep
