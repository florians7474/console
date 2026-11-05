# Fennec — Project State

Fennec is a web-based launcher (Flask, fullscreen) that runs several
Wi-Fi / network pentest tools from a single Raspberry Pi 5 with a
touchscreen. Each tool is independent but chainable, driven from tiles.

Repo (public): github.com/florians7474/fennec
Local folder on the Pi: ~/console  (SSH: ssh florian@fennec.local)

## Legal scope
Offensive actions (cracking, Bjorn scan, connecting) are only allowed on
a user-declared whitelist of networks, identified by BSSID
(liste_blanche.json, not tracked in git). Pwnagotchi wide capture stays free.
Ethernet access = implicit authorization (physical act), so the BSSID lock
only applies to Wi-Fi.

## Hardware

### Owned / final build
- Raspberry Pi 5, Raspberry Pi OS 64-bit desktop (hostname fennec, user florian)
- Screen: Waveshare 3.5" RPi LCD (C), resistive touch, 480x320, high-speed SPI
  (the UI is built at 480x320, fits without rework; needs the SPI overlay
  enabled in config.txt at mount time)
- Wi-Fi USB adapter (monitor mode, required — Pi 5 built-in chip can't do it):
  Alfa AWUS036AXM (MediaTek MT7921AU), plugs straight into USB. Auto-detected
  by Fennec (first wlan* whose phy advertises monitor mode), no config needed.
- GPS: VK-162 USB GPS module (waterproof, for the Carte / wardriving module —
  tags each captured network with its position)

### Test gear
- Alfa AWUS036ACH (Realtek RTL8812AU) — validated in monitor mode as wlan1,
  used as the test adapter

## Ports
Fennec :5000 · Pwnagotchi :8080 · Bjorn :8000

## Modules
| Module | Role | Status |
|--------|------|--------|
| Pwnagotchi | Handshake capture (jayofelony fork) | Done (install + control + head display) |
| Bjorn | LAN scan/attack (infinition/Bjorn) | Done (install + control + live console) |
| Raton | Offline WPA cracking (custom) | Done (9-stage engine + intelligence base, tested live); GPU export to polish |
| Connexion | Join a whitelisted network (Wi-Fi lock step 2) | Stub only (stores target in memory, no real nmcli yet) |
| Vigie | Network radar (devices on the LAN) | Done v1 (real ARP scan via nmap, mine/unknown by MAC); per-device traffic/domains later |
| Carte | Wardriving map (WiGLE-style) | To do |

Pwnagotchi and Bjorn run "behind" Fennec: installed on the Pi, started/stopped
by their tile via systemd services kept disabled at boot (sudoers rules allow
florian to systemctl start/stop them without a password). Only Raton is
coded in-house.

## Connection, scan and lists
- Header badge: shows the Pi's real connection, read live from nmcli/hostname
  at each page load — Ethernet, Wi-Fi + SSID, or Offline. It replaces the old
  simulated "current network" value, so it never claims a Wi-Fi when the Pi is
  on Ethernet.
- Allowed networks (liste_blanche.json, gitignored): the BSSID whitelist, with
  per-entry key, inline edit, and a Clear all that empties it.
- Scan page, two tabs:
  - Direct scan: a live nmcli scan stored as a snapshot (scan_direct.json,
    gitignored). "Scan" from Allowed networks runs it; "Rescan" refreshes it;
    Clear all empties the snapshot (it stays empty until the next scan).
  - Spotted by Pwnagotchi: lists the .pcap captures; Clear all deletes them via
    a small sudo helper (/usr/local/bin/fennec-clear-handshakes).
- All Clear all buttons use an in-page 480x320 confirm dialog, not the browser's
  native popup (which is unusable on the kiosk touchscreen).
- Bjorn's stopped screen names the network and /24 subnet it will scan (or asks
  to connect when offline), so the target is obvious before pressing Start.

## Vigie (device radar)
- Real ARP scan of the current /24 via nmap -sn, run as root by a dedicated
  sudo helper (/usr/local/bin/fennec-netscan, allowed in fennec.sudoers). Needs
  root so nmap returns MAC addresses + vendor (OUI).
- Each device: IP, MAC, vendor. The Pi (own IP) is tagged "This Pi", the default
  gateway "Router"; both are excluded from the unknown count.
- Mine vs unknown is keyed by MAC (stable across IP changes), stored in
  mes_appareils.json (gitignored). One tap on an "Unknown" chip marks it mine.
- Unknown devices sort to the top; header shows "N devices · M unknown".
- Scans on open; "Rescan" reloads. Traffic/domains per device is v2 (MITM).

## Raton — cracking engine
Local cracking = aircrack-ng (stable on ARM, CPU). hashcat is NOT used locally
(segfaults on the Pi's PoCL/OpenCL ARM backend); it is reserved for the GPU
export only. Raton is the smart orchestrator.

### Pi constraints (hard rules)
- Everything in flux (pipes) or in RAM (/dev/shm), no large wordlist written
  to the SD card.
- Only tiny files on disk: the box-profile knowledge base and the run log.
- Everything else stays in RAM.

### Honesty guardrail
Raton reveals WEAK keys. On a modern box with a random factory key it passes
quickly, concludes "probably sound", and points to the GPU export. It never
promises to crack long random WPA2.

### Intelligence = knowledge base (not self-learning)
The intelligence comes from external knowledge about how boxes and humans make
weak keys, not from Raton's own (rare) successes. At launch Raton reads the
BSSID (OUI -> vendor) and the ESSID, queries the local box-profile base, and
derives a targeted plan. Key point: you cannot deduce password length/shape
from the hash (PBKDF2 destroys it) — the only possible narrowing comes from
knowing the target.

Sources now integrated:
- Box-profile base: profils_box.json (prefix ESSID -> vendor/model/algo),
  routed to routerkeygen-cli (compiled in /usr/local/bin/routerkeygen-cli).
  An ESSID flagged "ignore" (e.g. community hotspot) skips the factory stage.
- ESSID profiling: raton_essid_gen.py mutates words extracted from a custom
  network name (case, leet, suffixes, name+digits), capped at 100k, written to
  /dev/shm so aircrack keeps a real counter and progress bar.
- Real cracked keys: SecLists probable-v2-wpa-top4800 (tiny, WPA-specific).
- Rules: John default --rules on the 10k list (OneRule too heavy for the Pi CPU).

### Stage plan (escalation, stops as soon as a key falls)
9 stages, in order:
1. Factory default keys (profils_box.json + routerkeygen)
2. ESSID profiling (custom-name words + mutations; skipped if the name is generic)
3. Real cracked keys (probable-wpa-top4800)
4. Birth dates (DDMMYYYY / YYYYMMDD)
5. 10k common passwords
6. Keyboard patterns
7. 10k common + John mutation rules
8. John incremental, 1h cap
9. rockyou random (shuf), 1h cap

Stages 8 and 9 are long "deep" passes with a TIME gauge (0% -> 100% over 1h,
hard stop via a watchdog thread). Short stages show the key counter + bar;
the time stages show mm:ss / 60:00 and the live candidate, not a key count.

Length filter: every stage feeds aircrack only candidates of 8..63 chars
(WPA minimum), via awk on the pipe or a filtered /dev/shm copy, so no invalid
short candidate is ever shown or tested.

### Already done on Raton
- 9-stage escalation built, reordered, and tested live on a real Bbox.
- Robustness score recalibrated for the 9 stages: stage where the box falls =
  its grade (Critical / Very weak / Weak / Moderate / Robust).
  _score_robustesse() in raton_engine.py, shown on result.
- Auto key write: a cracked key is written back into the whitelist by BSSID
  (route /cassage/etat in app.py).
- GPU export: /cassage/export/<bssid> converts the .pcap to .hc22000
  (hcxpcapngtool) and returns the hashcat command; "GPU" button -> cassage_gpu.html.
- Robust stdout reading (errors="replace") so a non-UTF8 byte from aircrack no
  longer freezes a stage.
- install.sh now folds all Raton deps (routerkeygen build, hcxtools, John,
  wordlists: 10k-common, probable-wpa-top4800, rockyou).
- No-handshake guard: before cracking, Raton checks the capture really holds a
  4-way handshake (aircrack-ng). If not, the Test button is greyed out in the
  capture list ("· no handshake") and the result reads "No usable handshake"
  instead of a misleading "Robust". Presence is cached per file (mtime + size).

### Work left on Raton
- Clearer GPU export — one-click handoff, so the user has nothing to copy:
  - a download button for the already-generated .hc22000 file
  - a ready command pointing at that file + a known wordlist, e.g.
    hashcat -m 22000 fennec_<box>.hc22000 rockyou.txt -r best64.rule
  - optionally a one-click script (crack.sh / crack.bat) that fetches the
    wordlist if needed and launches hashcat, so there is zero manual step

## Install (showcase)
One command on a fresh Pi: git clone the repo, then ./install.sh (idempotent,
adapts to any user/path; generates a random bettercap password; nothing
sensitive in the repo). Installs Fennec, Pwnagotchi, Bjorn (clone + dedicated
venv + systemd services), and all Raton deps (routerkeygen, hcxtools, John,
nmap, and the wordlists 10k-common / probable-wpa / rockyou fetched from
SecLists).
Notes:
- On Raspberry Pi OS Trixie, routerkeygen's qmake may default to Qt6; if the
  CLI build fails on a fresh Pi, force Qt5 (qmake -qt5).
- Bjorn's upstream requirements.txt pins old versions (e.g. Pillow 9.4.0) that
  do not build on Python 3.13; install.sh installs from a pinned
  system/bjorn-requirements.txt instead (Pillow 11.1.0).
- Bjorn needs more than its 15 upstream deps on Python 3.13 / Trixie: the
  display/GPIO stack (gpiozero, lgpio, rpi-lgpio, colorzero) for the e-paper
  init, and legacy-cgi because Python 3.13 removed the stdlib cgi module.
  python3-dev is installed so netifaces (sdist only) compiles.
- SPI is enabled by the installer (raspi-config nonint do_spi 0); without it
  /dev/spidev0.0 is missing and Bjorn crashes on e-paper init. Reboot once
  after install so it takes effect.
- Bjorn's web server is patched at install time (allow_reuse_address + a fixed
  port 8000): upstream jumps to 8001 on a quick Stop/Start because the port is
  still in TIME_WAIT, which breaks the embedded view. The patch keeps it on 8000.

## Dev loop
Edited directly on the Pi and pushed from there.
Editing any project file: nano ~/console/<file>.

## Other work left (outside Raton)
- Wi-Fi lock step 2: make the Connexion tile real via nmcli on wlan0
  (connect/disconnect, real state, refuse if no key and point to Raton).
  Currently a stub that only stores the target in memory.
- Wi-Fi lock step 3: Bjorn start gate (ethernet allowed; on Wi-Fi the connected
  BSSID must be in the whitelist)
- Vigie v2: per-device traffic / contacted domains (needs MITM via bettercap;
  v1 already does the real device radar — ARP scan, mine vs unknown by MAC)
- Carte: build the wardriving map (uses the VK-162 GPS)

## Known issues
- Flask runs in debug (debug=True), leaves 2 processes on :5000 ("Address
  already in use" on restart). Workaround: sudo kill $(sudo lsof -t -i :5000).
  Will disappear once Fennec runs as a systemd service. Not urgent.
