# Fennec 🦊

Web-based launcher for Wi-Fi pentest modes on a Raspberry Pi 5.

Fennec turns a Raspberry Pi 5 and a touchscreen into a small Wi-Fi auditing console. A full-screen web interface, five tiles, one tool running at a time. Each module stays independent and starts or stops on demand straight from the screen.

The project also serves as a hands-on sandbox for learning offensive security. The goal is not to crack strong WPA2 but to reveal weak keys on your own networks.

## Preview

> _(interface screenshot to add here: `docs/preview.png`)_

## Modules

| Tile | Role | Status |
|------|------|--------|
| **Pwnagotchi** | Passive Wi-Fi handshake capture | ✅ Working |
| **Bjorn** | Network reconnaissance and targeted attacks | ✅ Working |
| **Raton** | Offline WPA cracking on your own captures | ✅ Working |
| **Vigie** | Network radar + per-device traffic watch | ✅ Working |
| **Carte** | Map of captures by GPS location | 🚧 Phase 1 |

The header shows the Pi's live connection, Ethernet, Wi-Fi with its SSID, or Offline, and opens the allowed-networks manager where you scan for networks and pick the ones you are allowed to test.

**Pwnagotchi**, **Bjorn**, **Raton** and **Vigie** are operational: automatic installation, control from the tile, and a live view inside the interface.

- **Pwnagotchi** captures handshakes in the background and mirrors its head live in the tile.
- **Bjorn** scans and probes the network the Pi is currently on. The screen names that network and its subnet before you start, so there is no doubt about what is being audited, and its live console streams inside the tile.
- **Raton** runs a 9-stage escalation on your own captures (factory keys, ESSID profiling, known cracked keys, dates, common passwords, keyboard patterns, mutation rules, then two one-hour deep passes) and grades the key's robustness, with a one-step handoff to GPU cracking. Captures with no usable handshake are flagged and cannot be tested, so a network is never wrongly reported as robust.
- **Vigie** scans the current subnet (ARP via nmap) and lists every device with its IP, MAC and vendor. Unknown devices are sorted to the top with an amber accent, a one-tap chip marks a device as yours, and a header count ("6 devices · 2 unknown") tells you at a glance whether something is on the network that shouldn't be. Tap a device to open its detail: open ports and services, a guessed device type (PC, phone, printer, camera, NAS…), hostname, MAC and vendor. You can rename any device (saved per network), and the **Watch** mode turns Vigie into a passive monitor: a bettercap MITM of the whole subnet reveals the domains each device contacts, with a persistent, timestamped history kept per network.
- **Carte** plots captured handshakes on a live map using the position read at capture time (Pwnagotchi's GPS plugin writes a `.gps.json` next to each handshake when a fix is available). Markers are colour-coded by whitelist status, and tapping one adds that network to the allowed list. Phase 1 (geolocating captures) is in; full wardriving comes next.

## Legal scope

Fennec is built to audit your own networks. Offensive actions (cracking, targeted reconnaissance) are restricted to a whitelist of networks you declare yourself, identified by their BSSID. Passive capture stays open because it only listens to the surrounding airspace, like any Wi-Fi analyzer.

Only use this tool on networks you own or have written permission to test. Any other use is illegal.

## Hardware

- Raspberry Pi 5
- 3.5" touchscreen (Waveshare 480x320 reference)
- USB Wi-Fi adapter with monitor mode (tested with an Alfa AWUS036AXM, MediaTek MT7921AU chipset)
- Optional: VK-162 USB GPS module (for the Carte / wardriving module)
- microSD card, 32 GB or more, Raspberry Pi OS 64-bit (desktop)

The Pi 5 built-in Wi-Fi does not support monitor mode, so a compatible USB adapter is required. The interface is detected automatically, no adapter name is hardcoded.

## Installation

A single command on a freshly flashed Pi:

    git clone https://github.com/florians7474/fennec.git
    cd fennec
    ./install.sh

The script is idempotent and adapts to any user. It installs the system packages (including nmap), enables SPI (needed by Bjorn's e-paper display), sets up Pwnagotchi in an isolated venv, compiles pwngrid, builds routerkeygen-cli, installs Bjorn in its own venv from a pinned requirements file that works on Python 3.13, downloads the Raton wordlists (10k-common, probable-wpa and rockyou from SecLists), generates a random bettercap password, and configures all systemd services. It also installs Fennec as a systemd service and sets up the Waveshare 3.5" touchscreen end to end: the SPI overlay, X, and a Chromium kiosk that starts Fennec full-screen at boot. No sensitive data is stored in the repository.

Reboot once after the install. On boot the touchscreen comes up on its own and Fennec starts as a service, showing the interface full-screen in a Chromium kiosk.

## Usage

After the reboot the interface runs full-screen on the touchscreen and is ready to use. You can also reach it from a browser on the local network:

    http://fennec.local:5000/

Click or tap a tile to activate the matching module.

## Architecture

- **Fennec**: Flask app that drives the modules without modifying them (port 5000)
- **Pwnagotchi**: jayofelony fork in an isolated venv, driven through systemd
- **Bjorn**: infinition/Bjorn, driven through systemd, live console in the tile
- **Raton**: in-house WPA cracking engine (aircrack-ng, CPU), staged escalation, GPU export
- **Vigie**: in-house device radar and traffic monitor (nmap for discovery and port scans, bettercap MITM for per-device domains, persistent per-network history)
- Automatic detection of the monitor-mode Wi-Fi adapter at launch

## Roadmap

- [x] Fennec launcher and tile interface
- [x] Pwnagotchi module (install, control, display)
- [x] One-command installer (SPI enabled, works on a fresh card in one pass)
- [x] Touchscreen display and Chromium kiosk auto-starting at boot
- [x] Bjorn module (install, control, live console)
- [x] Raton module (WPA cracking, 9-stage escalation, GPU export)
- [x] Live connection indicator (Ethernet / Wi-Fi / Offline)
- [x] Vigie module (device radar, per-device recon, naming, and traffic watch via MITM)
- [x] Carte module – phase 1 (geolocate captured handshakes on a live map)
- [ ] Real Wi-Fi join/disconnect from the connection manager (nmcli)
- [ ] Carte module – phase 2 (full wardriving: map every network, offline tiles)
