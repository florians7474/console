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
- Raspberry Pi 5, Raspberry Pi OS 64-bit desktop (hostname fennec, user florian)
- Reference screen: 3.5" 480x320 (UI built at this size)
- Wi-Fi USB adapter required for monitor mode (Pi 5 built-in chip can't do it):
  Alfa AWUS036ACH (RTL8812AU) for tests, AWUS036AXM (MT7921AU) for final use
- Auto-detection: first wlan* whose phy advertises monitor mode is picked (no
  hardcoded interface name)

## Ports
Fennec :5000 · Pwnagotchi :8080 · Bjorn :8000

## Modules
| Module | Role | Status |
|--------|------|--------|
| Pwnagotchi | Handshake capture (jayofelony fork) | Done (install + control + head display) |
| Bjorn | LAN scan/attack (infinition/Bjorn) | Done (install + control + live console) |
| Raton | Offline WPA cracking (custom) | Engine done, intelligence to build |
| Vigie | Network monitor (own devices only) | To do |
| Carte | Wardriving map (WiGLE-style) | To do |

Pwnagotchi and Bjorn run "behind" Fennec: installed on the Pi, started/stopped
by their tile via systemd services kept disabled at boot (sudoers rules allow
florian to systemctl start/stop them without a password). Only Raton is
coded in-house.

## Raton — cracking engine
Local cracking = aircrack-ng (stable on ARM, CPU). hashcat is NOT used locally
(segfaults on the Pi's PoCL/OpenCL ARM backend); it is reserved for the GPU
export only. Raton is the smart orchestrator.

### Pi constraints (hard rules)
- Everything in flux (pipes), no large wordlist written to the SD card.
- Only tiny files on disk: the box-profile knowledge base and the run log.
- Everything else stays in RAM.

### Honesty guardrail
Raton reveals WEAK keys. On a modern box with a random factory key it passes
quickly, concludes "probably sound", and points to the GPU export. It never
promises to crack long random WPA2.

### Intelligence = knowledge base (not self-learning)
The intelligence comes from external knowledge about how boxes and humans make
weak keys, not from Raton's own (rare) successes. At launch Raton reads the
BSSID (OUI -> vendor) and the ESSID, queries a local box-profile base, and
derives a targeted plan. Key point: you cannot deduce password length/shape
from the hash (PBKDF2 destroys it) — the only possible narrowing comes from
knowing the target.

Sources to integrate:
- Box-profile base: schema inspired by Airbash / crackdefault.sh (BSSID/ESSID
  -> vulnerable model -> factory-key algo) + routerkeygen-cli (45 vendors,
  already compiled in /usr/local/bin/routerkeygen-cli)
- ESSID profiling: hcxtools (hcxeiutool / hcxessid.rule) — extract words from a
  custom network name, mutate with John
- Real cracked keys: WPA-Sec (dwpa, Alex Stanev) + SecLists WiFi-WPA
  probable-v2-wpa-top4800 (tiny, WPA-specific)
- Rules: lightweight best64 only (OneRule too heavy for the Pi CPU)

### Final stage plan (escalation, stops as soon as a key falls)
1. Targeted factory keys (box-profile base + routerkeygen)  [NEW]
2. ESSID profiling (custom-name words + John rules; skipped if generic)  [NEW]
3. Real cracked keys (WPA-Sec + probable-wpa-top4800)  [NEW]
4. Birth dates (DDMMYYYY / YYYYMMDD)  [exists]
5. 10k common passwords  [exists]
6. John incremental, random, 1h cap  [adjust existing]
7. rockyou random read, 1h cap  [adjust existing]

Stages 6 and 7 are long "deep" passes (big-attempt feel, like Pwnagotchi/Bjorn)
with a TIME gauge (0% -> 100% over 1h, hard stop). Short stages keep the
animated "streaming" bar.

### Already built stages (keep, just reorder)
factory keys (routerkeygen), common passwords, keyboard patterns, dates,
dictionary+rules (John: john --stdout --rules | aircrack-ng -w -), rockyou.

### Already done on Raton
- Robustness score: stage where the box falls = its grade (Critical / Very weak
  / Weak / Robust). _score_robustesse() in raton_engine.py, shown on result.
- Auto key write: a cracked key is written back into the whitelist by BSSID
  (route /cassage/etat in app.py).
- GPU export: /cassage/export/<bssid> converts the .pcap to .hc22000
  (hcxpcapngtool) and returns the hashcat command; "GPU" button -> cassage_gpu.html.

### Work left on Raton
1. Build the box-profile base (the intelligence socle) + ESSID profiling stage
   + real-cracked-keys stage
2. Reorder ETAGES per the plan; add 1h time cap + time gauge to John & rockyou;
   switch John to incremental and rockyou to random read
3. Clearer GPU export (a real .hc22000 download button)
4. Fold Raton's install into install.sh (routerkeygen, hcxtools, John, wordlists)

## Install (showcase)
One command on a fresh Pi: git clone the repo, then ./install.sh (idempotent,
adapts to any user/path; generates a random bettercap password; nothing
sensitive in the repo).

## Dev loop
Claude cannot push from its session (missing GitHub rights). Florian edits on
the Pi and pushes. Editing any project file: nano ~/console/<file>.

## Other work left (outside Raton)
- Wi-Fi lock step 2: real Connexion tile via nmcli on wlan0 (connect/disconnect,
  real state, refuse if no key and point to Raton)
- Wi-Fi lock step 3: Bjorn start gate (ethernet allowed; on Wi-Fi the connected
  BSSID must be in the whitelist)
- Fold Bjorn install into install.sh; update README (Bjorn 🚧 -> ✅)
- Modules Vigie and Carte

## Known issues
- Flask runs in debug (debug=True), leaves 2 processes on :5000 ("Address
  already in use" on restart). Workaround: sudo kill $(sudo lsof -t -i :5000).
  Will disappear once Fennec runs as a systemd service. Not urgent.
