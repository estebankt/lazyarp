# lazyarp

ARP-based network scanner with a terminal UI. Think Fing, but keyboard-driven and fast.

```
┌ Devices (4) ────────────────────┬ Device Details ──────────────────────────────┐
│ > ● 🌐 192.168.1.1  router.loc… │   IP Address : 192.168.1.42                  │
│   ● 💻 192.168.1.42 marios-mbp  │   MAC Address: A4:C3:F0:12:34:56             │
│   ● 📱 192.168.1.55 iPhone-Mari │   Vendor     : Apple, Inc.                   │
│   ○ 📺 192.168.1.88 LG-SmartTV  │   Hostname   : marios-mbp.local              │
│                                  │   Device Type: Computer                      │
│                                  │   OS         : macOS                         │
│                                  │   Status     : ● Active                      │
│                                  │   Last Seen  : 01:14:32 UTC                  │
│                                  │   mDNS Svcs  : _ssh._tcp, _afpovertcp._tcp   │
│                                  │                                              │
│                                  │   Open Ports                                 │
│                                  │      22  SSH                                 │
│                                  │     548  AFP                                 │
└──────────────────────────────────┴──────────────────────────────────────────────┘
┌ lazyarp [DONE]  iface: eth0 ─────────────────────────────────────────────────────┐
│ [01:14:35] Sweep complete — 4 devices found                                      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Features

- **ARP scanning** — active sweep (raw sockets) or passive mode (no privileges needed)
- **Device fingerprinting** — type and OS inferred from OUI vendor, open ports, mDNS services, and SSDP announcements
- **mDNS listener** — passively captures Bonjour/Avahi announcements to identify hostnames and service types
- **SSDP/UPnP listener** — detects smart TVs, NAS boxes, routers, and printers via UPnP discovery
- **Port scanner** — 19 common ports checked concurrently on navigation (500 ms timeout)
- **Emoji device tags** — 🌐 Router · 💻 Computer · 📱 Phone · 📺 Smart TV · 🖨 Printer · 💡 IoT · 🗄 NAS · 📡 AP
- **Live filter** — search by IP, MAC, vendor, hostname, or device type
- **Yank to clipboard** — copy selected IP with `y` (persists after exit on Wayland via `wl-copy`)

## Requirements

Raw socket access is needed for active mode. Without it the app falls back to passive mode automatically.

- **Linux (active)**: `cap_net_raw` capability or `sudo`
- **Linux (passive)**: no privileges required — reads `/proc/net/arp`
- **macOS**: `sudo` (active) or runs passive without it

libpcap must be installed:
- Arch/Manjaro: `sudo pacman -S libpcap`
- Ubuntu/Debian: `apt install libpcap-dev`
- Fedora/RHEL: `dnf install libpcap-devel`
- macOS: ships with Xcode tools, no action needed

Clipboard yank on Wayland requires `wl-clipboard`; on X11 use `xclip` or `xsel`.

## Build

```bash
# download OUI database (one-time, ~3.5 MB)
curl -L -o assets/oui.csv https://standards-oui.ieee.org/oui/oui.csv

cargo build --release
```

## Run

```bash
# Linux — active mode (raw sockets)
sudo ./target/release/lazyarp

# Linux — grant capability so you don't need sudo every time
sudo setcap cap_net_raw+eip ./target/release/lazyarp
./target/release/lazyarp

# Linux — passive mode (no privileges; falls back automatically)
./target/release/lazyarp

# macOS
sudo ./target/release/lazyarp
```

## Keys

| key | action |
|-----|--------|
| `j` / `k` | navigate up / down |
| `Enter` | trigger port scan on selected device |
| `y` | yank selected IP to clipboard |
| `/` | filter devices (IP, MAC, vendor, hostname, type) |
| `Esc` | clear filter |
| `r` | rescan now |
| `q` / `Ctrl+C` | quit |

Selecting a device automatically triggers a port scan (cached per device). Devices that stop responding are marked inactive (`○`) rather than removed.

## How it works

Four concurrent tasks share a single `Arc<Mutex<AppState>>`:

1. **ARP scanner** — sweeps the subnet every 30 s (active: raw ARP via pnet; passive: UDP-probe + `/proc/net/arp`). Devices unseen for two sweeps become inactive.
2. **mDNS listener** — joins the `224.0.0.251:5353` multicast group and parses DNS-SD PTR records to extract hostnames and service types (`_ssh._tcp`, `_airplay._tcp`, `_googlecast._tcp`, etc.).
3. **SSDP listener** — joins `239.255.255.250:1900`, issues an M-SEARCH probe, and parses `SERVER:`/`NT:` headers to identify routers, NAS boxes, smart TVs, and printers.
4. **TUI** — crossterm event loop rendering at ~60 fps; port scans and clipboard writes run in their own spawned tasks.

MAC prefixes are matched against the embedded IEEE OUI table (~30 k entries, compiled in). Device type is inferred in priority order: OUI hint → port scan → mDNS → SSDP.

## Caveats

- Only scans the local subnet of the automatically selected interface
- Subnets larger than /16 are skipped (too many hosts)
- Port scan covers 19 common ports, not a full nmap sweep
- mDNS bind may fail if `avahi-daemon` already holds port 5353 (logged; app continues)
