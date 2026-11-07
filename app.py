import os
import re
import json
import time
import atexit
import socket
import raton_engine
import vigie_monitor
from flask import Flask, render_template, redirect, url_for, abort, request, jsonify

app = Flask(__name__)

BASE = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE = os.path.join(BASE, "liste_blanche.json")
MINE_FILE = os.path.join(BASE, "mes_appareils.json")
SCAN_FILE  = os.path.join(BASE, "scan_direct.json")
NAMES_FILE  = os.path.join(BASE, "noms_appareils.json")   # {reseau: {mac: nom}}
HISTORY_FILE  = os.path.join(BASE, "historique_trafic.json")  # {reseau: {mac: {domaine: ts}}}

etat = {"mode_actif": None, "reseau": None}

MODES = {
    "pwnagotchi": {"nom": "Pwnagotchi", "classe": "pwn",   "url": None},
    "cracking":    {"nom": "Raton",      "classe": "cass",  "url": None},
    "bjorn":      {"nom": "Bjorn",      "classe": "bjorn", "url": None},
}

# ---------- JSON files ----------

def _load(fichier):
    try:
        with open(fichier, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def _save(fichier, data):
    with open(fichier, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_whitelist():
    return _load(WHITELIST_FILE)

def save_whitelist(reseaux):
    _save(WHITELIST_FILE, reseaux)

def load_mine():
    return _load(MINE_FILE)   # list of device ids declared "mine"

def save_mine(ids):
    _save(MINE_FILE, ids)

def load_scan():
    return _load(SCAN_FILE)   # last saved direct scan

def save_scan(reseaux):
    _save(SCAN_FILE, reseaux)

# ---------- Modes ----------

import subprocess
import urllib.request
import base64

# systemd services managed by each mode, in start order
SERVICES = {
    "pwnagotchi": ["bettercap", "pwngrid-peer", "pwnagotchi"],
    "bjorn": ["bjorn", "bjorn-console"],
}

import glob

def detect_monitor_iface():
    """Return the name of the first wlan interface capable of monitor mode, else None."""
    for chemin in sorted(glob.glob("/sys/class/net/wlan*")):
        iface = os.path.basename(chemin)
        try:
            with open(os.path.join(chemin, "phy80211/name")) as f:
                phy = f.read().strip()
            infos = subprocess.run(
                ["iw", "phy", phy, "info"],
                capture_output=True, text=True, timeout=10,
            ).stdout
            # We target the supported-modes section
            if "* monitor" in infos:
                return iface
        except Exception:
            continue
    return None

def _systemctl(action, service):
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/systemctl", action, service],
            check=True, capture_output=True, timeout=20,
        )
        return True
    except Exception:
        return False

def start(mode):
    for service in SERVICES.get(mode, []):
        _systemctl("start", service)

def stop(mode):
    for service in reversed(SERVICES.get(mode, [])):
        _systemctl("stop", service)

def est_actif(service):
    try:
        r = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False

@app.route("/pwna-ui")
def pwna_ui():
    from flask import Response
    url = "http://127.0.0.1:8080/ui"
    ident = base64.b64encode(b"pwnagotchi:pwnagotchi").decode()
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {ident}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return Response(r.read(), mimetype="image/png")
    except Exception:
        abort(503)

def connection_state():
    """The Pi's real network connection: ethernet, wifi (+SSID) or none."""
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "TYPE,STATE,CONNECTION", "device", "status"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return {"type": None, "nom": "Offline"}
    eth = wifi = None
    for ligne in r.stdout.splitlines():
        fields = ligne.split(":")
        if len(fields) < 3 or fields[1] != "connected":
            continue
        typ, conn = fields[0], ":".join(fields[2:])
        if typ == "ethernet" and not eth:
            eth = conn
        elif typ == "wifi" and not wifi:
            wifi = conn
    if eth:
        return {"type": "ethernet", "nom": "Ethernet"}
    if wifi:
        return {"type": "wifi", "nom": wifi or "Wi-Fi"}
    return {"type": None, "nom": "Offline"}

def local_ip():
    """The Pi's first non-loopback IPv4, or None."""
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    for tok in r.stdout.split():
        if tok.count(".") == 3 and not tok.startswith("127."):
            return tok
    return None

def local_subnet():
    """The Pi's /24 subnet (e.g. 192.168.1.0/24), or None."""
    ip = local_ip()
    return ".".join(ip.split(".")[:3]) + ".0/24" if ip else None

def passerelle_ip():
    """Default gateway IP (the router), or None."""
    try:
        r = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    m = re.search(r"default via ([\d.]+)", r.stdout)
    return m.group(1) if m else None

def scan_network():
    """LAN devices via nmap -sn (dedicated sudo script). IP, MAC, vendor."""
    try:
        r = subprocess.run(
            ["sudo", "-n", "/usr/local/bin/fennec-netscan"],
            capture_output=True, text=True, timeout=90,
        )
    except Exception:
        return []
    appareils, courant = [], None
    for ligne in r.stdout.splitlines():
        m = re.search(r"Nmap scan report for (.+)", ligne)
        if m:
            cible = m.group(1).strip()
            mip = re.search(r"\(([\d.]+)\)", cible)
            ip = mip.group(1) if mip else cible
            courant = {"ip": ip, "mac": None, "vendor": None}
            appareils.append(courant)
            continue
        mmac = re.search(r"MAC Address:\s*([0-9A-Fa-f:]{17})\s*(?:\((.*)\))?", ligne)
        if mmac and courant is not None:
            courant["mac"] = mmac.group(1).upper()
            v = (mmac.group(2) or "").strip()
            courant["vendor"] = v or None
    return appareils

def vigie_devices():
    """Enriched list for Vigie: type, 'mine', unknown; unknowns first."""
    mienne = local_ip()
    passerelle = passerelle_ip()
    miens = set(load_mine())
    out = []
    for a in scan_network():
        pi = (a["ip"] == mienne)
        routeur = (a["ip"] == passerelle)
        mac = a["mac"]
        mien = (mac in miens)
        inconnu = not pi and not routeur and not mien
        out.append({
            "ip": a["ip"],
            "mac": mac,
            "nom": custom_name(mac) or a["vendor"] or ("This Pi" if pi else ("Router" if routeur else "Unknown device")),
            "type": "pi" if pi else ("router" if routeur else "device"),
            "pi": pi,
            "routeur": routeur,
            "mien": mien,
            "inconnu": inconnu,
        })
    # Unknowns first, then by IP (numeric order on the octets)
    def ip_key(d):
        try:
            return tuple(int(x) for x in d["ip"].split("."))
        except Exception:
            return (999,)
    out.sort(key=lambda d: (not d["inconnu"], ip_key(d)))
    last_scan.clear()
    last_scan.update({d["ip"]: d for d in out})
    return out

last_scan = {}

def arp_mac(ip):
    """MAC of an IP from the ARP cache (without re-scanning), or None."""
    try:
        r = subprocess.run(["ip", "neigh", "show", ip],
                           capture_output=True, text=True, timeout=5)
        m = re.search(r"lladdr ([0-9a-f:]{17})", r.stdout, re.I)
        return m.group(1).upper() if m else None
    except Exception:
        return None

def device_pour(ip):
    """Build a device detail for an IP, even outside the last scan."""
    mac = arp_mac(ip)
    pi = (ip == local_ip())
    routeur = (ip == passerelle_ip())
    mien = bool(mac) and mac in set(load_mine())
    nom = custom_name(mac) or ("This Pi" if pi else ("Router" if routeur else "Unknown device"))
    return {"ip": ip, "mac": mac, "vendor": None, "nom": nom,
            "type": "pi" if pi else ("router" if routeur else "device"),
            "pi": pi, "routeur": routeur, "mien": mien,
            "inconnu": not (pi or routeur or mien)}

def host_name(ip):
    """Reverse DNS de l'IP, ou None."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

PORTS_VIGIE = ("21,22,23,25,53,80,110,135,139,143,443,445,515,554,587,631,993,"
               "995,1723,3306,3389,5000,5357,5900,8000,8080,8443,9100,32400,"
               "37777,49152")

def scan_ports(ip):
    """Open TCP ports (targeted list, rootless connect scan, fast)."""
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip or ""):
        return []
    try:
        r = subprocess.run(
            ["nmap", "-sT", "-Pn", "-n", "-T4", "--max-retries", "1",
             "--host-timeout", "25s", "-p", PORTS_VIGIE, "--open", ip],
            capture_output=True, text=True, timeout=40,
        )
    except Exception:
        return []
    ports = []
    for ligne in r.stdout.splitlines():
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", ligne.strip())
        if m:
            ports.append({"port": int(m.group(1)), "service": m.group(2)})
    return ports

def guess_type(ports, vendor):
    """Guess the device type from the open ports, then the vendor."""
    svc = {p["port"] for p in ports}
    if 9100 in svc or 631 in svc:
        return "Printer"
    if 554 in svc or 8554 in svc or 37777 in svc:
        return "IP camera"
    if 445 in svc or 139 in svc:
        if 3389 in svc or 5357 in svc:
            return "Windows PC"
        return "File share / NAS"
    if 22 in svc:
        return "Linux / server"
    if 80 in svc or 443 in svc or 8080 in svc:
        return "Web device / IoT"
    v = (vendor or "").lower()
    if any(k in v for k in ["apple", "samsung", "xiaomi", "huawei", "google", "oneplus", "oppo"]):
        return "Phone / mobile"
    if "raspberry" in v:
        return "Raspberry Pi"
    return "Unknown"

# ---------- Vigie: network identity, custom names, traffic history ----------

def network_id():
    """Stable id of the current network: the router's MAC, else the subnet."""
    pg = passerelle_ip()
    if pg:
        try:
            r = subprocess.run(["ip", "neigh", "show", pg],
                               capture_output=True, text=True, timeout=5)
            m = re.search(r"lladdr ([0-9a-f:]{17})", r.stdout, re.I)
            if m:
                return m.group(1).upper()
        except Exception:
            pass
    return local_subnet() or "default"

def custom_name(mac):
    """User-given name for a device (this network), or None."""
    if not mac:
        return None
    noms = _load(NAMES_FILE)
    if not isinstance(noms, dict):
        return None
    return noms.get(network_id(), {}).get(mac.upper())

def set_name(mac, nom):
    noms = _load(NAMES_FILE)
    if not isinstance(noms, dict):
        noms = {}
    rid = network_id()
    noms.setdefault(rid, {})
    nom = (nom or "").strip()[:40]
    if nom:
        noms[rid][mac.upper()] = nom
    else:
        noms[rid].pop(mac.upper(), None)
    _save(NAMES_FILE, noms)

# Traffic history kept in memory, flushed to disk from time to time.
_hist = None
_hist_dirty = False
_hist_last = 0.0

def _history_load():
    global _hist
    if _hist is None:
        h = _load(HISTORY_FILE)
        _hist = h if isinstance(h, dict) else {}
    return _hist

def _history_flush(force=False):
    global _hist_dirty, _hist_last
    if _hist is None or (not _hist_dirty and not force):
        return
    if not force and (time.time() - _hist_last) < 20:
        return
    _save(HISTORY_FILE, _hist)
    _hist_dirty = False
    _hist_last = time.time()

def merge_traffic(mac, live):
    """Merge the live domains (dict domain->ts) into the device history."""
    global _hist_dirty
    if not mac:
        return dict(live)
    h = _history_load()
    rid = network_id()
    dev = h.setdefault(rid, {}).setdefault(mac.upper(), {})
    for dom, ts in live.items():
        if dom not in dev or ts > dev[dom]:
            dev[dom] = ts
            _hist_dirty = True
    _history_flush()
    return dev

@app.route("/")
def home():
    mode_actif = etat["mode_actif"]
    # Raton runs in a thread, not a service: the dot follows the engine's real state.
    if mode_actif == "cracking" and not raton_engine.crack_state.get("actif"):
        mode_actif = None
        etat["mode_actif"] = None
    if mode_actif == "vigie" and not vigie_monitor.monitor_state.get("actif"):
        mode_actif = None
        etat["mode_actif"] = None
    return render_template("home.html", actif=mode_actif, connection=connection_state())

HANDSHAKES_DIR = "/etc/pwnagotchi/handshakes"

_hs_cache = {}

def capture_a_handshake(fichier):
    """Whether a capture holds a handshake, cached per file (mtime+size)."""
    chemin = os.path.join(HANDSHAKES_DIR, fichier)
    try:
        st = os.stat(chemin)
        cle = (st.st_mtime, st.st_size)
    except OSError:
        return False
    hit = _hs_cache.get(chemin)
    if hit and hit[0] == cle:
        return hit[1]
    val = raton_engine.a_un_handshake(chemin)
    _hs_cache[chemin] = (cle, val)
    return val

def read_handshakes():
    captures = {}
    try:
        fichiers = os.listdir(HANDSHAKES_DIR)
    except OSError:
        return []
    for f in fichiers:
        if not f.endswith(".pcap"):
            continue
        base = f[:-5]
        if "_" not in base:
            continue
        nom, _, brut = base.rpartition("_")
        brut = brut.lower()
        if len(brut) != 12 or not all(c in "0123456789abcdef" for c in brut):
            continue
        bssid = ":".join(brut[i:i+2] for i in range(0, 12, 2)).upper()
        if bssid not in captures:
            captures[bssid] = {"nom": nom, "bssid": bssid, "fichier": f}
    return sorted(captures.values(), key=lambda c: c["nom"].lower())

def scan_direct():
    try:
        res = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,BSSID", "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, timeout=25
        )
    except Exception:
        return []
    reseaux = {}
    for ligne in res.stdout.splitlines():
        fields = re.split(r"(?<!\\):", ligne)
        if len(fields) < 3:
            continue
        ssid = fields[0].replace("\\:", ":").strip()
        signal = fields[1].strip()
        bssid = fields[2].replace("\\:", ":").upper().strip()
        if not bssid or bssid in reseaux:
            continue
        try:
            dbm = int(signal) // 2 - 100
        except ValueError:
            dbm = None
        reseaux[bssid] = {"nom": ssid or "(hidden)", "bssid": bssid, "signal": dbm}
    return sorted(reseaux.values(), key=lambda r: -(r["signal"] if r["signal"] is not None else -999))

@app.route("/mode/<nom>")
def mode(nom):
    if nom not in MODES:
        abort(404)

    if nom == "cracking":
        e = raton_engine.crack_state
        if e.get("actif"):
            capture = next((c for c in read_handshakes()
                            if c["bssid"] == e.get("bssid")), None)
            if capture:
                return render_template("crack_result.html", c=capture)
        deja = {r["bssid"] for r in load_whitelist()}
        captures = read_handshakes()
        for cap in captures:
            # Only check for a handshake on allowed networks (the only ones that
            # show a Test button), to avoid useless scans.
            cap["handshake"] = cap["bssid"] in deja and capture_a_handshake(cap["fichier"])
        return render_template("cracking.html", captures=captures, deja=deja)

    if nom == "pwnagotchi":
        actif = est_actif("pwnagotchi")
        etat["mode_actif"] = "pwnagotchi" if actif else etat["mode_actif"]
        url_ui = "/pwna-ui"
        return render_template("mode.html", cle=nom, infos=MODES[nom], actif=actif,
                               url_ui=url_ui, url_iframe=None)
    if nom == "bjorn":
        actif = est_actif("bjorn")
        etat["mode_actif"] = "bjorn" if actif else etat["mode_actif"]
        hote = request.host.split(":")[0]
        url_iframe = f"http://{hote}:8000/"
        conn = connection_state()
        reseau_scan = {"type": conn["type"], "nom": conn["nom"],
                       "sous_reseau": local_subnet()}
        return render_template("mode.html", cle=nom, infos=MODES[nom], actif=actif,
                               url_ui=None, url_iframe=url_iframe, reseau_scan=reseau_scan)
    actif = (etat["mode_actif"] == nom)
    return render_template("mode.html", cle=nom, infos=MODES[nom], actif=actif,
                           url_ui=None, url_iframe=None)

@app.route("/toggle/<nom>")
def toggle(nom):
    if nom not in MODES:
        return redirect(url_for("home"))
    if vigie_monitor.monitor_state["actif"]:   # another mode starts: stop Vigie monitoring
        vigie_monitor.stop()
    actuel = etat["mode_actif"]
    if actuel == "vigie":
        actuel = None
    if actuel == nom:
        stop(nom)
        etat["mode_actif"] = None
    else:
        if actuel:
            stop(actuel)
        start(nom)
        etat["mode_actif"] = nom
    return redirect(url_for("mode", nom=nom))

@app.route("/cracking/test/<bssid>")
def crack_test(bssid):
    autorises = {r["bssid"] for r in load_whitelist()}
    if bssid not in autorises:
        return redirect(url_for("mode", nom="cracking"))
    capture = next((c for c in read_handshakes() if c["bssid"] == bssid), None)
    if not capture:
        return redirect(url_for("mode", nom="cracking"))
    # Raton takes over: stop the running modes (Pwnagotchi / Bjorn / Vigie)
    if est_actif("pwnagotchi"):
        stop("pwnagotchi")
    if est_actif("bjorn"):
        stop("bjorn")
    if vigie_monitor.monitor_state["actif"]:
        vigie_monitor.stop()
    etat["mode_actif"] = "cracking"
    etat["reseau"] = capture["nom"]
    pcap = os.path.join(HANDSHAKES_DIR, capture["fichier"])
    raton_engine.lancer(pcap, bssid, capture["nom"])
    return render_template("crack_result.html", c=capture)

@app.route("/cracking/export/<bssid>")
def crack_export(bssid):
    autorises = {r["bssid"] for r in load_whitelist()}
    if bssid not in autorises:
        return jsonify({"ok": False, "erreur": "Network not in allowed list"})
    capture = next((c for c in read_handshakes() if c["bssid"] == bssid), None)
    if not capture:
        return jsonify({"ok": False, "erreur": "No handshake for this network"})
    pcap = os.path.join(HANDSHAKES_DIR, capture["fichier"])
    sortie = "/tmp/raton_export_" + bssid.replace(":", "") + ".hc22000"
    try:
        subprocess.run(
            ["hcxpcapngtool", "-o", sortie, pcap],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as ex:
        return jsonify({"ok": False, "erreur": "Conversion failed: " + str(ex)})
    try:
        with open(sortie) as f:
            hash_hc = f.read().strip()
    except OSError:
        hash_hc = ""
    if not hash_hc:
        return jsonify({"ok": False, "erreur": "No crackable handshake in this capture"})
    fichier = os.path.basename(sortie)
    profil = raton_engine.profile_for_essid(capture["nom"])
    fmt = (profil or {}).get("format") or {}
    masque = fmt.get("mask", "")
    if profil and profil.get("algo") == "mask" and "?" in masque:
        commande = "cd ~/Downloads && hashcat -m 22000 " + fichier + " -a 3 " + masque
        type_attaque = "mask"
    else:
        commande = ("cd ~/Downloads && hashcat -m 22000 " + fichier
                    + " /usr/share/wordlists/rockyou.txt"
                    + " -r /usr/share/hashcat/rules/best64.rule")
        type_attaque = "wordlist"
    return jsonify({
        "ok": True,
        "fichier": fichier,
        "hash": hash_hc,
        "commande": commande,
        "telecharger": "/cracking/download/" + bssid,
        "type": type_attaque,
    })

@app.route("/cracking/download/<bssid>")
def crack_download(bssid):
    autorises = {r["bssid"] for r in load_whitelist()}
    if bssid not in autorises:
        abort(404)
    sortie = "/tmp/raton_export_" + bssid.replace(":", "") + ".hc22000"
    if not (os.path.exists(sortie) and os.path.getsize(sortie) > 0):
        capture = next((c for c in read_handshakes() if c["bssid"] == bssid), None)
        if not capture:
            abort(404)
        pcap = os.path.join(HANDSHAKES_DIR, capture["fichier"])
        try:
            subprocess.run(["hcxpcapngtool", "-o", sortie, pcap],
                           capture_output=True, text=True, timeout=30)
        except Exception:
            abort(404)
    if not (os.path.exists(sortie) and os.path.getsize(sortie) > 0):
        abort(404)
    from flask import send_file
    return send_file(sortie, as_attachment=True,
                     download_name=os.path.basename(sortie),
                     mimetype="text/plain")

@app.route("/cracking/gpu/<bssid>")
def crack_gpu(bssid):
    capture = next((c for c in read_handshakes() if c["bssid"] == bssid), None)
    nom = capture["nom"] if capture else bssid
    return render_template("crack_gpu.html", bssid=bssid, nom=nom)

@app.route("/cracking/state")
def crack_status():
    e = raton_engine.crack_state
    if e.get("trouve") and e.get("cle") and not e.get("enregistree"):
        reseaux = load_whitelist()
        for r in reseaux:
            if r["bssid"] == e.get("bssid"):
                r["cle"] = e["cle"]
                break
        save_whitelist(reseaux)
        e["enregistree"] = True
    return jsonify(e)

@app.route("/cracking/stop")
def crack_stop():
    raton_engine.stop()
    return jsonify({"ok": True})

@app.route("/map")
def map_view():
    deja = {r["bssid"] for r in load_whitelist()}
    points = []
    sans_position = 0
    for c in read_handshakes():
        chemin_gps = os.path.join(HANDSHAKES_DIR, c["fichier"].replace(".pcap", ".gps.json"))
        try:
            with open(chemin_gps, "r", encoding="utf-8") as f:
                g = json.load(f)
            lat, lon = g.get("Latitude"), g.get("Longitude")
        except (FileNotFoundError, json.JSONDecodeError):
            lat = lon = None
        if lat and lon:
            points.append({
                "nom": c["nom"],
                "bssid": c["bssid"],
                "lat": lat,
                "lon": lon,
                "autorise": c["bssid"] in deja,
            })
        else:
            sans_position += 1
    return render_template("map.html", points=points, sans_position=sans_position)

# ---------- Connection ----------

@app.route("/connection")
def connection():
    return render_template("connection.html", reseaux=load_whitelist(), actuel=etat["reseau"])

@app.route("/connection/to/<bssid>")
def connection_to(bssid):
    cible = next((r for r in load_whitelist() if r["bssid"] == bssid), None)
    if cible:
        etat["reseau"] = cible
    return redirect(url_for("connection"))

@app.route("/connection/stop")
def connection_stop():
    etat["reseau"] = None
    return redirect(url_for("connection"))

# ---------- Vigie ----------

@app.route("/vigie")
def vigie():
    return render_template("vigie.html")

@app.route("/vigie/data")
def vigie_data():
    appareils = vigie_devices()
    inconnus = sum(1 for a in appareils if a["inconnu"])
    return jsonify({"appareils": appareils, "total": len(appareils), "inconnus": inconnus})

@app.route("/vigie/mine/<mac>")
def vigie_mine(mac):
    mac = mac.upper()
    ids = load_mine()
    if mac not in ids:
        ids.append(mac)
        save_mine(ids)
    return jsonify({"ok": True})

@app.route("/vigie/notmine/<mac>")
def vigie_notmine(mac):
    mac = mac.upper()
    ids = [i for i in load_mine() if i.upper() != mac]
    save_mine(ids)
    return jsonify({"ok": True})

@app.route("/vigie/device/<ip>")
def vigie_device(ip):
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return redirect(url_for("vigie"))
    d = last_scan.get(ip) or device_pour(ip)
    return render_template("vigie_detail.html", d=d)

@app.route("/vigie/ports/<ip>")
def vigie_ports(ip):
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return jsonify({"ports": [], "type": "Unknown", "hote": None})
    d = last_scan.get(ip) or {}
    ports = scan_ports(ip)
    return jsonify({"ports": ports,
                    "type": guess_type(ports, d.get("vendor")),
                    "hote": host_name(ip)})

@app.route("/vigie/monitor/start")
def vigie_monitor_start():
    # Monitoring takes over: stop the other active modes.
    if etat["mode_actif"] in SERVICES:
        stop(etat["mode_actif"])
    if raton_engine.crack_state.get("actif"):
        raton_engine.stop()
    ip = local_ip()
    prefix = ".".join(ip.split(".")[:3]) + "." if ip else None
    ok = vigie_monitor.start(prefix)
    if ok:
        etat["mode_actif"] = "vigie"
    return jsonify({"actif": vigie_monitor.monitor_state["actif"]})

@app.route("/vigie/monitor/stop")
def vigie_monitor_stop():
    vigie_monitor.stop()
    _history_flush(force=True)
    if etat["mode_actif"] == "vigie":
        etat["mode_actif"] = None
    return jsonify({"actif": False})

@app.route("/vigie/monitor/data")
def vigie_monitor_data():
    return jsonify(vigie_monitor.snapshot())

@app.route("/vigie/monitor/force")
def vigie_monitor_force():
    # Only while watching: the DoT/DoH block sits on the MITM-forwarded traffic.
    if not vigie_monitor.monitor_state["actif"]:
        return jsonify({"actif": False, "force": False})
    force = vigie_monitor.forcer_dns(request.args.get("on") == "1")
    return jsonify({"actif": True, "force": force})

@app.route("/vigie/traffic/<ip>")
def vigie_traffic(ip):
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return jsonify({"actif": False, "domaines": []})
    d = last_scan.get(ip) or {}
    mac = d.get("mac") or arp_mac(ip)
    hote = (host_name(ip) or "").lower().rstrip(".")
    live = vigie_monitor.timestamps([c for c in (ip, hote) if c])
    dom_ts = merge_traffic(mac, live)   # fusionne live + historique persistant
    items = sorted(dom_ts.items(), key=lambda kv: kv[1], reverse=True)
    return jsonify({
        "actif": vigie_monitor.monitor_state["actif"],
        "vpn": vigie_monitor.vpn_info([c for c in (ip, hote) if c]),
        "domaines": [{"d": dom, "t": ts} for dom, ts in items],
    })

@app.route("/vigie/rename/<mac>", methods=["POST"])
def vigie_rename(mac):
    set_name(mac, request.form.get("nom", ""))
    return jsonify({"ok": True, "nom": custom_name(mac)})

# ---------- Whitelist (routes) ----------

@app.route("/whitelist")
def whitelist_page():
    return render_template("whitelist_page.html", reseaux=load_whitelist())

@app.route("/whitelist/add", methods=["POST"])
def whitelist_add():
    nom = request.form.get("nom", "").strip()
    bssid = request.form.get("bssid", "").strip().upper()
    cle = request.form.get("cle", "").strip()
    retour = request.form.get("retour", "")
    source = request.form.get("source", "direct")
    if bssid:
        reseaux = load_whitelist()
        if not any(r["bssid"] == bssid for r in reseaux):
            entree = {"nom": nom or "Unnamed", "bssid": bssid}
            if cle:
                entree["cle"] = cle
            reseaux.append(entree)
            save_whitelist(reseaux)
    if retour == "scan":
        return redirect(url_for("scan", source=source))
    return redirect(url_for("whitelist_page"))

@app.route("/whitelist/edit", methods=["POST"])
def whitelist_edit():
    bssid = request.form.get("bssid", "").strip().upper()
    nom = request.form.get("nom", "").strip()
    cle = request.form.get("cle", "").strip()
    reseaux = load_whitelist()
    for r in reseaux:
        if r["bssid"] == bssid:
            r["nom"] = nom or r.get("nom", "Unnamed")
            if cle:
                r["cle"] = cle
            else:
                r.pop("cle", None)
            break
    save_whitelist(reseaux)
    return redirect(url_for("whitelist_page"))

@app.route("/whitelist/remove/<bssid>")
def whitelist_remove(bssid):
    reseaux = [r for r in load_whitelist() if r["bssid"] != bssid]
    save_whitelist(reseaux)
    if etat["reseau"] and etat["reseau"]["bssid"] == bssid:
        etat["reseau"] = None
    return redirect(url_for("whitelist_page"))

@app.route("/whitelist/reset")
def whitelist_reset():
    save_whitelist([])
    etat["reseau"] = None
    source = request.args.get("source")
    if source:
        return redirect(url_for("scan", source=source))
    return redirect(url_for("whitelist_page"))

@app.route("/scan")
def scan():
    source = request.args.get("source", "direct")
    if source == "pwna":
        reseaux = read_handshakes()
    else:
        source = "direct"
        if request.args.get("rescan"):
            save_scan(scan_direct())
            return redirect(url_for("scan", source="direct"))
        reseaux = load_scan()
    deja = {r["bssid"] for r in load_whitelist()}
    return render_template("scan.html", reseaux=reseaux, deja=deja, source=source)

@app.route("/scan/vider/<source>")
def scan_clear(source):
    if source == "pwna":
        try:
            subprocess.run(
                ["sudo", "-n", "/usr/local/bin/fennec-clear-handshakes"],
                check=True, capture_output=True, timeout=20,
            )
        except Exception:
            pass
        return redirect(url_for("scan", source="pwna"))
    save_scan([])
    return redirect(url_for("scan", source="direct"))

@app.route("/power/<action>", methods=["POST"])
def power(action):
    # Power off / reboot the Pi from the screen (keyboard-less kiosk).
    if action not in ("poweroff", "reboot"):
        abort(404)
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/bin/systemctl", action],
            check=True, capture_output=True, timeout=20,
        )
    except Exception:
        pass
    return ("", 204)

# On Fennec shutdown, stop bettercap so the network is not left under ARP
# spoofing (otherwise the connection stays disrupted after exit).
atexit.register(vigie_monitor.stop)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FENNEC_DEBUG", "1") == "1")
