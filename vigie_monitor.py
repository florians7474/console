"""Moteur de monitoring Vigie : MITM (bettercap) pour router le trafic par le Pi,
+ capture SNI/DNS via tshark (le moteur de Wireshark), qui lit le SNI du TLS
classique (TCP/443) ET du QUIC (UDP/443, HTTP/3) — ce que bettercap ne faisait
pas. Agrégé par appareil, clé = IP source (donnée directement par tshark).

Le script sudo /usr/local/bin/fennec-monitor lance bettercap (arp.spoof) puis
tshark en sortie « champs » tabulés :  ip.src <TAB> sni <TAB> dns
Une seule colonne de domaine est renseignée par ligne ; on prend la première.
"""
import os
import re
import signal
import subprocess
import threading
import time
from collections import deque, OrderedDict

etat_monitor = {
    "actif": False,
    "depuis": None,
    "hotes": {},                 # ip -> OrderedDict(domaine -> ts)
    "brut": deque(maxlen=250),   # dernières lignes brutes (réglage)
}

_proc = None
_thread = None
_verrou = threading.Lock()

_RE_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IGNORER_DOM = re.compile(r"(\.lan|\.local|\.arpa|\.home|\.internal)$", re.I)


def _noter(ip, domaine):
    with _verrou:
        d = etat_monitor["hotes"].setdefault(ip, OrderedDict())
        d[domaine] = time.time()
        while len(d) > 60:
            d.popitem(last=False)


def _traiter(ligne):
    champs = ligne.rstrip("\n").split("\t")
    if len(champs) < 2:
        return
    src = champs[0].strip()
    if not _RE_IP.match(src):        # on ne garde que les sources IPv4
        return
    dom = ""
    for c in champs[1:]:             # premier champ domaine non vide (sni, puis dns)
        c = c.strip().split(",")[0]  # tshark peut concaténer plusieurs valeurs
        if c:
            dom = c
            break
    if not dom:
        return
    dom = dom.lower().rstrip(".")
    if not dom or _RE_IP.match(dom) or _IGNORER_DOM.search(dom):
        return
    _noter(src, dom)


def _lire(proc):
    for ligne in iter(proc.stdout.readline, ""):
        ligne = ligne.rstrip("\n")
        if not ligne:
            continue
        etat_monitor["brut"].append(ligne)
        try:
            _traiter(ligne)
        except Exception:
            pass


def demarrer(prefixe=None):
    """Lance le script (bettercap + tshark) et le thread de lecture."""
    global _proc, _thread
    if etat_monitor["actif"]:
        return True
    try:
        _proc = subprocess.Popen(
            ["sudo", "-n", "/usr/local/bin/fennec-monitor"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            bufsize=1, start_new_session=True,
        )
    except Exception:
        _proc = None
        return False
    with _verrou:
        etat_monitor["actif"] = True
        etat_monitor["depuis"] = time.time()
        etat_monitor["hotes"] = {}
        etat_monitor["brut"].clear()
    _thread = threading.Thread(target=_lire, args=(_proc,), daemon=True)
    _thread.start()
    return True


def arreter():
    """Coupe bettercap + tshark proprement (tout le groupe de processus)."""
    global _proc
    p = _proc
    if p and p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            try:
                p.wait(timeout=5)
            except Exception:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except Exception:
            try:
                p.terminate()
            except Exception:
                pass
    _proc = None
    with _verrou:
        etat_monitor["actif"] = False


def horodates(cles):
    """Domaines + dernier timestamp pour une ou plusieurs clés (IP)."""
    out = {}
    with _verrou:
        for cle in cles:
            for dom, ts in etat_monitor["hotes"].get(cle, {}).items():
                if dom not in out or ts > out[dom]:
                    out[dom] = ts
    return out


def instantane():
    """Vue JSON-able : actif + domaines par appareil + dernières lignes brutes."""
    with _verrou:
        hotes = {ip: [k for k, _ in sorted(d.items(), key=lambda kv: kv[1], reverse=True)]
                 for ip, d in etat_monitor["hotes"].items()}
        brut = list(etat_monitor["brut"])[-60:]
    return {"actif": etat_monitor["actif"], "hotes": hotes, "brut": brut}
