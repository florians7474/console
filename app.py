import os
import re
import json
import raton_engine
from flask import Flask, render_template, redirect, url_for, abort, request, jsonify

app = Flask(__name__)

BASE = os.path.dirname(os.path.abspath(__file__))
FICHIER_LISTE = os.path.join(BASE, "liste_blanche.json")
FICHIER_MIENS = os.path.join(BASE, "mes_appareils.json")

etat = {"mode_actif": None, "reseau": None}

MODES = {
    "pwnagotchi": {"nom": "Pwnagotchi", "classe": "pwn",   "url": None},
    "cassage":    {"nom": "Raton",      "classe": "cass",  "url": None},
    "bjorn":      {"nom": "Bjorn",      "classe": "bjorn", "url": None},
}

RESEAUX_GEO = [
    {"nom": "Livebox-2A3F", "bssid": "34:27:92:AA:2A:3F", "lat": 48.8566, "lon": 2.3522, "signal": -41},
    {"nom": "Freebox-Flo",  "bssid": "F4:CA:E5:11:88:0C", "lat": 48.8573, "lon": 2.3510, "signal": -55},
    {"nom": "SFR_1B20",     "bssid": "68:A3:78:1B:20:9D", "lat": 48.8558, "lon": 2.3541, "signal": -67},
    {"nom": "Bbox-6E1A",    "bssid": "00:1A:2B:6E:1A:44", "lat": 48.8580, "lon": 2.3533, "signal": -72},
    {"nom": "orange-FA22",  "bssid": "5C:DC:96:FA:22:10", "lat": 48.8551, "lon": 2.3505, "signal": -80},
]

# Simulated devices. "mine" is no longer hardcoded: it comes from mes_appareils.json.
APPAREILS_SIMULES = [
    {"id": "box",    "nom": "Router / Gateway",  "ip": "192.168.1.1",  "type": "router",
     "trafic": ["orange.fr", "dns.google", "ntp.org"]},
    {"id": "iph",    "nom": "Florian's iPhone",  "ip": "192.168.1.42", "type": "smartphone",
     "trafic": ["apple.com", "instagram.com", "whatsapp.net", "lemonde.fr", "google.com"]},
    {"id": "pc",     "nom": "Florian's PC",      "ip": "192.168.1.10", "type": "computer",
     "trafic": ["github.com", "cloudflare.com", "microsoft.com", "youtube.com", "digitechnologie.com"]},
    {"id": "tv",     "nom": "Living room TV",    "ip": "192.168.1.23", "type": "TV",
     "trafic": ["samsung.com", "netflix.com", "youtube.com"]},
    {"id": "inc",    "nom": "Unknown device",    "ip": "192.168.1.55", "type": "unknown",
     "trafic": ["akamai.net", "amazonaws.com"]},
    {"id": "invite", "nom": "Galaxy (guest)",    "ip": "192.168.1.60", "type": "smartphone",
     "trafic": ["snapchat.com", "tiktok.com", "google.com"]},
]

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

@app.route("/")
def accueil():
    return render_template("home.html", actif=etat["mode_actif"], reseau=etat["reseau"])

HANDSHAKES_DIR = "/etc/pwnagotchi/handshakes"

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
        return render_template("cassage.html", captures=lire_handshakes(), deja=deja)

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
        return render_template("mode.html", cle=nom, infos=MODES[nom], actif=actif,
                               url_ui=None, url_iframe=url_iframe)
    actif = (etat["mode_actif"] == nom)
    return render_template("mode.html", cle=nom, infos=MODES[nom], actif=actif,
                           url_ui=None, url_iframe=None)

@app.route("/basculer/<nom>")
def basculer(nom):
    if nom not in MODES:
        return redirect(url_for("accueil"))
    actuel = etat["mode_actif"]
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
    # Raton prend la main : couper les modes qui tournent (Pwnagotchi / Bjorn)
    if est_actif("pwnagotchi"):
        arreter("pwnagotchi")
    if est_actif("bjorn"):
        arreter("bjorn")
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
    points = [dict(p, autorise=(p["bssid"] in deja)) for p in RESEAUX_GEO]
    return render_template("carte.html", points=points)

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
    miens = set(charger_miens())
    return render_template("vigie.html", appareils=APPAREILS_SIMULES, reseau=etat["reseau"], miens=miens)

@app.route("/vigie/mien/<id_app>")
def vigie_mien(id_app):
    ids = charger_miens()
    if id_app not in ids and any(a["id"] == id_app for a in APPAREILS_SIMULES):
        ids.append(id_app)
        sauver_miens(ids)
    return redirect(url_for("vigie"))

@app.route("/vigie/pasmien/<id_app>")
def vigie_pasmien(id_app):
    ids = [i for i in charger_miens() if i != id_app]
    sauver_miens(ids)
    return redirect(url_for("vigie"))

@app.route("/vigie/trafic/<id_app>")
def vigie_trafic(id_app):
    if not etat["reseau"]:
        return redirect(url_for("vigie"))
    if id_app not in set(charger_miens()):          # LOCK: only your declared devices
        return redirect(url_for("vigie"))
    appareil = next((a for a in APPAREILS_SIMULES if a["id"] == id_app), None)
    if not appareil:
        return redirect(url_for("vigie"))
    return render_template("vigie_trafic.html", a=appareil)

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
        reseaux = scan_direct()
    deja = {r["bssid"] for r in charger_liste()}
    return render_template("scan.html", reseaux=reseaux, deja=deja, source=source)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
