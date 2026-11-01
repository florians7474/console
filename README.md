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
| **Raton** | Offline WPA cracking on your own captures | 🚧 Planned |
| **Bjorn** | Network reconnaissance and targeted attacks | 🚧 Planned |
| **Vigie** | Network monitor (connected devices, contacted domains) | 🚧 Planned |
| **Carte** | Network mapping (wardriving) | 🚧 Planned |

For now only **Pwnagotchi** is operational: automatic installation, control from the tile (starting and stopping the services), and a live display of its face inside the interface.

## Legal scope

Fennec is built to audit your own networks. Offensive actions (cracking, targeted reconnaissance) are restricted to a whitelist of networks you declare yourself, identified by their BSSID. Passive capture stays open because it only listens to the surrounding airspace, like any Wi-Fi analyzer.

Only use this tool on networks you own or have written permission to test. Any other use is illegal.

## Hardware

- Raspberry Pi 5
- 3.5" touchscreen (Waveshare 480x320 reference)
- USB Wi-Fi adapter with monitor mode (tested with an Alfa AWUS036ACH, Realtek RTL8812AU chipset)
- microSD card, 32 GB or more, Raspberry Pi OS 64-bit (desktop)

The Pi 5 built-in Wi-Fi does not support monitor mode, so a compatible USB adapter is required. The interface is detected automatically, no adapter name is hardcoded.

## Installation

A single command on a freshly flashed Pi:

    git clone https://github.com/florians7474/fennec.git
    cd fennec
    ./install.sh

The script is idempotent and adapts to any user. It installs the system packages, sets up Pwnagotchi in an isolated environment, compiles pwngrid, generates a random password for bettercap, and configures the services. No sensitive data is stored in the repository.

## Usage

Once installed, start Fennec and open the interface from a browser on the local network:

    http://fennec.local:5000/

Click a tile to activate the matching module.

## Architecture

- **Fennec**: Flask app that drives the modules without modifying them (port 5000)
- **Pwnagotchi**: jayofelony fork in an isolated venv, driven by Fennec through systemd
- Three services orchestrated in order: bettercap, then pwngrid-peer, then pwnagotchi
- Automatic detection of the monitor-mode Wi-Fi adapter at launch

## Roadmap

- [x] Fennec launcher and tile interface
- [x] Pwnagotchi module (install, control, display)
- [x] One-command installer
- [ ] Raton module (WPA cracking)
- [ ] Bjorn module
- [ ] Vigie module
- [ ] Carte module

