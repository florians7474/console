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
FICHIER_LISTE = os.path.join(BASE, "liste_blanche.json")
FICHIER_MIENS = os.path.join(BASE, "mes_appareils.json")
FICHIER_SCAN  = os.path.join(BASE, "scan_direct.json")
FICHIER_NOMS  = os.path.join(BASE, "noms_appareils.json")   # {reseau: {mac: nom}}
FICHIER_HIST  = os.path.join(BASE, "historique_trafic.json")  # {reseau: {mac: {domaine: ts}}}

etat = {"mode_actif": None, "reseau": None}

MODES = {
    "pwnagotchi": {"nom": "Pwnagotchi", "classe": "pwn",   "url": None},
    "cassage":    {"nom": "Raton",      "classe": "cass",  "url": None},
    "bjorn":      {"nom": "Bjorn",      "classe": "bjorn", "url": None},
}

# ---------- JSON files ----------

def _charger(fichier):
    try:
        with open(fichier, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def _sauver(fichier, data):
    with open(fichier, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def charger_liste():
    return _charger(FICHIER_LISTE)

def sauver_liste(reseaux):
    _sauver(FICHIER_LISTE, reseaux)

def charger_miens():
    return _charger(FICHIER_MIENS)   # list of device ids declared "mine"

def sauver_miens(ids):
    _sauver(FICHIER_MIENS, ids)

def charger_scan():
    return _charger(FICHIER_SCAN)   # dernier scan direct mémorisé

def sauver_scan(reseaux):
    _sauver(FICHIER_SCAN, reseaux)

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

def detecter_cle_monitor():
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

def demarrer(mode):
    for service in SERVICES.get(mode, []):
        _systemctl("start", service)

def arreter(mode):
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

def etat_connexion():
    """Vraie connexion réseau du Pi : ethernet, wifi (+SSID) ou rien."""
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "TYPE,STATE,CONNECTION", "device", "status"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return {"type": None, "nom": "Offline"}
    eth = wifi = None
    for ligne in r.stdout.splitlines():
        champs = ligne.split(":")
        if len(champs) < 3 or champs[1] != "connected":
            continue
        typ, conn = champs[0], ":".join(champs[2:])
        if typ == "ethernet" and not eth:
            eth = conn
        elif typ == "wifi" and not wifi:
            wifi = conn
    if eth:
        return {"type": "ethernet", "nom": "Ethernet"}
    if wifi:
        return {"type": "wifi", "nom": wifi or "Wi-Fi"}
    return {"type": None, "nom": "Offline"}

def ip_locale():
    """Première IPv4 non-loopback du Pi, ou None."""
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    for tok in r.stdout.split():
        if tok.count(".") == 3 and not tok.startswith("127."):
            return tok
    return None

def sous_reseau_local():
    """Sous-réseau /24 du Pi (ex. 192.168.1.0/24), ou None."""
    ip = ip_locale()
    return ".".join(ip.split(".")[:3]) + ".0/24" if ip else None

def passerelle_ip():
    """IP de la passerelle par défaut (la box), ou None."""
    try:
        r = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    m = re.search(r"default via ([\d.]+)", r.stdout)
    return m.group(1) if m else None

def scan_reseau():
    """Appareils du LAN via nmap -sn (script sudo dédié). IP, MAC, constructeur."""
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

def appareils_vigie():
    """Liste enrichie pour Vigie : type, 'à moi', inconnu ; inconnus en tête."""
    mienne = ip_locale()
    passerelle = passerelle_ip()
    miens = set(charger_miens())
    out = []
    for a in scan_reseau():
        pi = (a["ip"] == mienne)
        routeur = (a["ip"] == passerelle)
        mac = a["mac"]
        mien = (mac in miens)
        inconnu = not pi and not routeur and not mien
        out.append({
            "ip": a["ip"],
            "mac": mac,
            "nom": nom_perso(mac) or a["vendor"] or ("This Pi" if pi else ("Router" if routeur else "Unknown device")),
            "type": "pi" if pi else ("router" if routeur else "device"),
            "pi": pi,
            "routeur": routeur,
            "mien": mien,
            "inconnu": inconnu,
        })
    # Inconnus d'abord, puis par IP (ordre numérique sur les octets)
    def cle_ip(d):
        try:
            return tuple(int(x) for x in d["ip"].split("."))
        except Exception:
            return (999,)
    out.sort(key=lambda d: (not d["inconnu"], cle_ip(d)))
    _dernier_scan.clear()
    _dernier_scan.update({d["ip"]: d for d in out})
    return out

_dernier_scan = {}

def arp_mac(ip):
    """MAC d'une IP depuis le cache ARP (sans re-scanner), ou None."""
    try:
        r = subprocess.run(["ip", "neigh", "show", ip],
                           capture_output=True, text=True, timeout=5)
        m = re.search(r"lladdr ([0-9a-f:]{17})", r.stdout, re.I)
        return m.group(1).upper() if m else None
    except Exception:
        return None

def device_pour(ip):
    """Construit la fiche d'un appareil pour une IP, même hors du dernier scan."""
    mac = arp_mac(ip)
    pi = (ip == ip_locale())
    routeur = (ip == passerelle_ip())
    mien = bool(mac) and mac in set(charger_miens())
    nom = nom_perso(mac) or ("This Pi" if pi else ("Router" if routeur else "Unknown device"))
    return {"ip": ip, "mac": mac, "vendor": None, "nom": nom,
            "type": "pi" if pi else ("router" if routeur else "device"),
            "pi": pi, "routeur": routeur, "mien": mien,
            "inconnu": not (pi or routeur or mien)}

def nom_hote(ip):
    """Reverse DNS de l'IP, ou None."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

PORTS_VIGIE = ("21,22,23,25,53,80,110,135,139,143,443,445,515,554,587,631,993,"
               "995,1723,3306,3389,5000,5357,5900,8000,8080,8443,9100,32400,"
               "37777,49152")

def scan_ports(ip):
    """Ports TCP ouverts (liste ciblée, connect scan sans root, rapide)."""
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

def deviner_type(ports, vendor):
    """Devine le type d'appareil à partir des ports ouverts, puis du constructeur."""
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

# ---------- Vigie : identité réseau, noms persos, historique de trafic ----------

def id_reseau():
    """Identifiant stable du réseau courant : MAC de la box, sinon le sous-réseau."""
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
    return sous_reseau_local() or "default"

def nom_perso(mac):
    """Nom donné par l'utilisateur à un appareil (ce réseau), ou None."""
    if not mac:
        return None
    noms = _charger(FICHIER_NOMS)
    if not isinstance(noms, dict):
        return None
    return noms.get(id_reseau(), {}).get(mac.upper())

def definir_nom(mac, nom):
    noms = _charger(FICHIER_NOMS)
    if not isinstance(noms, dict):
        noms = {}
    rid = id_reseau()
    noms.setdefault(rid, {})
    nom = (nom or "").strip()[:40]
    if nom:
        noms[rid][mac.upper()] = nom
    else:
        noms[rid].pop(mac.upper(), None)
    _sauver(FICHIER_NOMS, noms)

# Historique de trafic gardé en mémoire, écrit sur disque de temps en temps.
_hist = None
_hist_dirty = False
_hist_last = 0.0

def _hist_charger():
    global _hist
    if _hist is None:
        h = _charger(FICHIER_HIST)
        _hist = h if isinstance(h, dict) else {}
    return _hist

def _hist_flush(force=False):
    global _hist_dirty, _hist_last
    if _hist is None or (not _hist_dirty and not force):
        return
    if not force and (time.time() - _hist_last) < 20:
        return
    _sauver(FICHIER_HIST, _hist)
    _hist_dirty = False
    _hist_last = time.time()

def fusionner_trafic(mac, live):
    """Fusionne les domaines live (dict domaine->ts) dans l'historique de l'appareil."""
    global _hist_dirty
    if not mac:
        return dict(live)
    h = _hist_charger()
    rid = id_reseau()
    dev = h.setdefault(rid, {}).setdefault(mac.upper(), {})
    for dom, ts in live.items():
        if dom not in dev or ts > dev[dom]:
            dev[dom] = ts
            _hist_dirty = True
    _hist_flush()
    return dev

@app.route("/")
def accueil():
    mode_actif = etat["mode_actif"]
    # Raton tourne dans un thread, pas un service : la pastille suit l'état réel du moteur.
    if mode_actif == "cassage" and not raton_engine.etat_cassage.get("actif"):
        mode_actif = None
        etat["mode_actif"] = None
    if mode_actif == "vigie" and not vigie_monitor.etat_monitor.get("actif"):
        mode_actif = None
        etat["mode_actif"] = None
    return render_template("home.html", actif=mode_actif, connexion=etat_connexion())

HANDSHAKES_DIR = "/etc/pwnagotchi/handshakes"

_hs_cache = {}

def capture_a_handshake(fichier):
    """Présence d'un handshake dans une capture, avec cache par fichier (mtime+taille)."""
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

def lire_handshakes():
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
        champs = re.split(r"(?<!\\):", ligne)
        if len(champs) < 3:
            continue
        ssid = champs[0].replace("\\:", ":").strip()
        signal = champs[1].strip()
        bssid = champs[2].replace("\\:", ":").upper().strip()
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

    if nom == "cassage":
        e = raton_engine.etat_cassage
        if e.get("actif"):
            capture = next((c for c in lire_handshakes()
                            if c["bssid"] == e.get("bssid")), None)
            if capture:
                return render_template("cassage_resultat.html", c=capture)
        deja = {r["bssid"] for r in charger_liste()}
        captures = lire_handshakes()
        for cap in captures:
            # On ne teste la présence du handshake que pour les réseaux autorisés
            # (les seuls qui affichent un bouton Test), pour éviter des scans inutiles.
            cap["handshake"] = cap["bssid"] in deja and capture_a_handshake(cap["fichier"])
        return render_template("cassage.html", captures=captures, deja=deja)

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
        conn = etat_connexion()
        reseau_scan = {"type": conn["type"], "nom": conn["nom"],
                       "sous_reseau": sous_reseau_local()}
        return render_template("mode.html", cle=nom, infos=MODES[nom], actif=actif,
                               url_ui=None, url_iframe=url_iframe, reseau_scan=reseau_scan)
    actif = (etat["mode_actif"] == nom)
    return render_template("mode.html", cle=nom, infos=MODES[nom], actif=actif,
                           url_ui=None, url_iframe=None)

@app.route("/basculer/<nom>")
def basculer(nom):
    if nom not in MODES:
        return redirect(url_for("accueil"))
    if vigie_monitor.etat_monitor["actif"]:   # un autre mode démarre : couper le monitoring Vigie
        vigie_monitor.arreter()
    actuel = etat["mode_actif"]
    if actuel == "vigie":
        actuel = None
    if actuel == nom:
        arreter(nom)
        etat["mode_actif"] = None
    else:
        if actuel:
            arreter(actuel)
        demarrer(nom)
        etat["mode_actif"] = nom
    return redirect(url_for("mode", nom=nom))

@app.route("/cassage/tester/<bssid>")
def cassage_tester(bssid):
    autorises = {r["bssid"] for r in charger_liste()}
    if bssid not in autorises:
        return redirect(url_for("mode", nom="cassage"))
    capture = next((c for c in lire_handshakes() if c["bssid"] == bssid), None)
    if not capture:
        return redirect(url_for("mode", nom="cassage"))
    # Raton prend la main : couper les modes qui tournent (Pwnagotchi / Bjorn / Vigie)
    if est_actif("pwnagotchi"):
        arreter("pwnagotchi")
    if est_actif("bjorn"):
        arreter("bjorn")
    if vigie_monitor.etat_monitor["actif"]:
        vigie_monitor.arreter()
    etat["mode_actif"] = "cassage"
    etat["reseau"] = capture["nom"]
    pcap = os.path.join(HANDSHAKES_DIR, capture["fichier"])
    raton_engine.lancer(pcap, bssid, capture["nom"])
    return render_template("cassage_resultat.html", c=capture)

@app.route("/cassage/export/<bssid>")
def cassage_export(bssid):
    autorises = {r["bssid"] for r in charger_liste()}
    if bssid not in autorises:
        return jsonify({"ok": False, "erreur": "Network not in allowed list"})
    capture = next((c for c in lire_handshakes() if c["bssid"] == bssid), None)
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
    commande = "hashcat -m 22000 " + os.path.basename(sortie) + " wordlist.txt"
    return jsonify({
        "ok": True,
        "fichier": os.path.basename(sortie),
        "hash": hash_hc,
        "commande": commande,
    })

@app.route("/cassage/gpu/<bssid>")
def cassage_gpu(bssid):
    capture = next((c for c in lire_handshakes() if c["bssid"] == bssid), None)
    nom = capture["nom"] if capture else bssid
    return render_template("cassage_gpu.html", bssid=bssid, nom=nom)

@app.route("/cassage/etat")
def cassage_etat():
    e = raton_engine.etat_cassage
    if e.get("trouve") and e.get("cle") and not e.get("enregistree"):
        reseaux = charger_liste()
        for r in reseaux:
            if r["bssid"] == e.get("bssid"):
                r["cle"] = e["cle"]
                break
        sauver_liste(reseaux)
        e["enregistree"] = True
    return jsonify(e)

@app.route("/cassage/stop")
def cassage_stop():
    raton_engine.arreter()
    return jsonify({"ok": True})

@app.route("/carte")
def carte():
    deja = {r["bssid"] for r in charger_liste()}
    points = []
    sans_position = 0
    for c in lire_handshakes():
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
    return render_template("carte.html", points=points, sans_position=sans_position)

# ---------- Connection ----------

@app.route("/connexion")
def connexion():
    return render_template("connexion.html", reseaux=charger_liste(), actuel=etat["reseau"])

@app.route("/connexion/vers/<bssid>")
def connexion_vers(bssid):
    cible = next((r for r in charger_liste() if r["bssid"] == bssid), None)
    if cible:
        etat["reseau"] = cible
    return redirect(url_for("connexion"))

@app.route("/connexion/stop")
def connexion_stop():
    etat["reseau"] = None
    return redirect(url_for("connexion"))

# ---------- Vigie ----------

@app.route("/vigie")
def vigie():
    return render_template("vigie.html")

@app.route("/vigie/data")
def vigie_data():
    appareils = appareils_vigie()
    inconnus = sum(1 for a in appareils if a["inconnu"])
    return jsonify({"appareils": appareils, "total": len(appareils), "inconnus": inconnus})

@app.route("/vigie/mien/<mac>")
def vigie_mien(mac):
    mac = mac.upper()
    ids = charger_miens()
    if mac not in ids:
        ids.append(mac)
        sauver_miens(ids)
    return jsonify({"ok": True})

@app.route("/vigie/pasmien/<mac>")
def vigie_pasmien(mac):
    mac = mac.upper()
    ids = [i for i in charger_miens() if i.upper() != mac]
    sauver_miens(ids)
    return jsonify({"ok": True})

@app.route("/vigie/appareil/<ip>")
def vigie_appareil(ip):
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return redirect(url_for("vigie"))
    d = _dernier_scan.get(ip) or device_pour(ip)
    return render_template("vigie_detail.html", d=d)

@app.route("/vigie/ports/<ip>")
def vigie_ports(ip):
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return jsonify({"ports": [], "type": "Unknown", "hote": None})
    d = _dernier_scan.get(ip) or {}
    ports = scan_ports(ip)
    return jsonify({"ports": ports,
                    "type": deviner_type(ports, d.get("vendor")),
                    "hote": nom_hote(ip)})

@app.route("/vigie/monitor/start")
def vigie_monitor_start():
    # Le monitoring prend la main : couper les autres modes actifs.
    if etat["mode_actif"] in SERVICES:
        arreter(etat["mode_actif"])
    if raton_engine.etat_cassage.get("actif"):
        raton_engine.arreter()
    ip = ip_locale()
    prefixe = ".".join(ip.split(".")[:3]) + "." if ip else None
    ok = vigie_monitor.demarrer(prefixe)
    if ok:
        etat["mode_actif"] = "vigie"
    return jsonify({"actif": vigie_monitor.etat_monitor["actif"]})

@app.route("/vigie/monitor/stop")
def vigie_monitor_stop():
    vigie_monitor.arreter()
    _hist_flush(force=True)
    if etat["mode_actif"] == "vigie":
        etat["mode_actif"] = None
    return jsonify({"actif": False})

@app.route("/vigie/monitor/data")
def vigie_monitor_data():
    return jsonify(vigie_monitor.instantane())

@app.route("/vigie/trafic/<ip>")
def vigie_trafic(ip):
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return jsonify({"actif": False, "domaines": []})
    d = _dernier_scan.get(ip) or {}
    mac = d.get("mac") or arp_mac(ip)
    hote = (nom_hote(ip) or "").lower().rstrip(".")
    live = vigie_monitor.horodates([c for c in (ip, hote) if c])
    dom_ts = fusionner_trafic(mac, live)   # fusionne live + historique persistant
    items = sorted(dom_ts.items(), key=lambda kv: kv[1], reverse=True)
    return jsonify({
        "actif": vigie_monitor.etat_monitor["actif"],
        "domaines": [{"d": dom, "t": ts} for dom, ts in items],
    })

@app.route("/vigie/nom/<mac>", methods=["POST"])
def vigie_nom(mac):
    definir_nom(mac, request.form.get("nom", ""))
    return jsonify({"ok": True, "nom": nom_perso(mac)})

# ---------- Whitelist (routes) ----------

@app.route("/liste")
def liste():
    return render_template("liste.html", reseaux=charger_liste())

@app.route("/liste/ajouter", methods=["POST"])
def liste_ajouter():
    nom = request.form.get("nom", "").strip()
    bssid = request.form.get("bssid", "").strip().upper()
    cle = request.form.get("cle", "").strip()
    retour = request.form.get("retour", "")
    source = request.form.get("source", "direct")
    if bssid:
        reseaux = charger_liste()
        if not any(r["bssid"] == bssid for r in reseaux):
            entree = {"nom": nom or "Unnamed", "bssid": bssid}
            if cle:
                entree["cle"] = cle
            reseaux.append(entree)
            sauver_liste(reseaux)
    if retour == "scan":
        return redirect(url_for("scan", source=source))
    return redirect(url_for("liste"))

@app.route("/liste/editer", methods=["POST"])
def liste_editer():
    bssid = request.form.get("bssid", "").strip().upper()
    nom = request.form.get("nom", "").strip()
    cle = request.form.get("cle", "").strip()
    reseaux = charger_liste()
    for r in reseaux:
        if r["bssid"] == bssid:
            r["nom"] = nom or r.get("nom", "Unnamed")
            if cle:
                r["cle"] = cle
            else:
                r.pop("cle", None)
            break
    sauver_liste(reseaux)
    return redirect(url_for("liste"))

@app.route("/liste/retirer/<bssid>")
def liste_retirer(bssid):
    reseaux = [r for r in charger_liste() if r["bssid"] != bssid]
    sauver_liste(reseaux)
    if etat["reseau"] and etat["reseau"]["bssid"] == bssid:
        etat["reseau"] = None
    return redirect(url_for("liste"))

@app.route("/liste/reset")
def liste_reset():
    sauver_liste([])
    etat["reseau"] = None
    source = request.args.get("source")
    if source:
        return redirect(url_for("scan", source=source))
    return redirect(url_for("liste"))

@app.route("/scan")
def scan():
    source = request.args.get("source", "direct")
    if source == "pwna":
        reseaux = lire_handshakes()
    else:
        source = "direct"
        if request.args.get("rescan"):
            sauver_scan(scan_direct())
            return redirect(url_for("scan", source="direct"))
        reseaux = charger_scan()
    deja = {r["bssid"] for r in charger_liste()}
    return render_template("scan.html", reseaux=reseaux, deja=deja, source=source)

@app.route("/scan/vider/<source>")
def scan_vider(source):
    if source == "pwna":
        try:
            subprocess.run(
                ["sudo", "-n", "/usr/local/bin/fennec-clear-handshakes"],
                check=True, capture_output=True, timeout=20,
            )
        except Exception:
            pass
        return redirect(url_for("scan", source="pwna"))
    sauver_scan([])
    return redirect(url_for("scan", source="direct"))

@app.route("/power/<action>", methods=["POST"])
def power(action):
    # Extinction / redémarrage du Pi depuis l'écran (kiosk sans clavier).
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

# À la fermeture de Fennec, couper bettercap pour ne pas laisser le réseau
# sous ARP spoofing (sinon la connexion reste perturbée après l'arrêt).
atexit.register(vigie_monitor.arreter)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FENNEC_DEBUG", "1") == "1")
