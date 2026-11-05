"""Moteur de monitoring Vigie : MITM (bettercap) + sniff du trafic, agrégé
par appareil (quels domaines chaque machine contacte). Lancé via le script
sudo fennec-monitor.

Format des lignes bettercap exploitées :
  [..] [net.sniff.https] sni <appareil> > https://<domaine>
  [..] [net.sniff.dns]   dns <résolveur> > <appareil> : <domaine> is <IPs>
L'appareil est un nom d'hôte (ex. iPhone.lan.), pas une IP ; on relie ensuite
ce nom à la fiche appareil par le reverse DNS côté Vigie. On indexe aussi par
l'IP résolue du nom quand c'est possible, pour fiabiliser la correspondance.
"""
import os
import re
import socket
import signal
import subprocess
import threading
import time
from collections import deque, OrderedDict

etat_monitor = {
    "actif": False,
    "depuis": None,
    "hotes": {},                 # clé (nom d'hôte ou IP) -> OrderedDict(domaine -> ts)
    "brut": deque(maxlen=250),   # dernières lignes brutes (réglage)
}

_proc = None
_thread = None
_verrou = threading.Lock()
_cache_ip = {}                   # nom d'hôte -> IP résolue (ou None)

_RE_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_SNI = re.compile(r"\bsni\s+(\S+)\s+>\s+https?://([^\s/]+)", re.I)
_RE_DNS = re.compile(r"\bdns\s+\S+\s+>\s+(\S+)\s+:\s+(\S+)", re.I)
_IGNORER_DOM = re.compile(r"(\.lan|\.local|\.arpa)$", re.I)


def _resoudre(nom):
    """Nom d'hôte -> IP (best-effort, mis en cache)."""
    if nom in _cache_ip:
        return _cache_ip[nom]
    ip = None
    try:
        ip = socket.gethostbyname(nom)
    except Exception:
        ip = None
    _cache_ip[nom] = ip
    return ip


def _cles(appareil):
    """Clés d'indexation d'un appareil : son nom, et son IP résolue si dispo."""
    a = appareil.strip().rstrip(".").lower()
    if not a or a in ("gateway",) or _RE_IP.match(a):
        # 'gateway'/une IP = résolveur, pas l'appareil demandeur utile
        if _RE_IP.match(a):
            return {a}
        return set()
    cles = {a}
    ip = _resoudre(a)
    if ip:
        cles.add(ip)
    return cles


def _noter(cle, domaine):
    with _verrou:
        d = etat_monitor["hotes"].setdefault(cle, OrderedDict())
        d[domaine] = time.time()
        while len(d) > 50:
            d.popitem(last=False)


def _traiter(ligne):
    bas = ligne.lower()
    if "sniff.mdns" in bas:
        return                      # mDNS = bruit .local, on ignore
    m = _RE_SNI.search(ligne)
    if m:
        appareil, dom = m.group(1), m.group(2)
    else:
        m = _RE_DNS.search(ligne)
        if not m:
            return
        appareil, dom = m.group(1), m.group(2)
    dom = dom.lower().rstrip(".")
    if not dom or _RE_IP.match(dom) or _IGNORER_DOM.search(dom):
        return
    for cle in _cles(appareil):
        _noter(cle, dom)


def _lire(proc, prefixe=None):
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
    """Lance bettercap (via le script sudo) et le thread de lecture."""
    global _proc, _thread
    if etat_monitor["actif"]:
        return True
    try:
        _proc = subprocess.Popen(
            ["sudo", "-n", "/usr/local/bin/fennec-monitor"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True,
        )
    except Exception:
        _proc = None
        return False
    with _verrou:
        etat_monitor["actif"] = True
        etat_monitor["depuis"] = time.time()
        etat_monitor["hotes"] = {}
        etat_monitor["brut"].clear()
    _cache_ip.clear()
    _thread = threading.Thread(target=_lire, args=(_proc, prefixe), daemon=True)
    _thread.start()
    return True


def arreter():
    """Coupe bettercap proprement (tout le groupe de processus)."""
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


def instantane():
    """Vue JSON-able : actif + domaines par appareil + dernières lignes brutes."""
    with _verrou:
        hotes = {cle: [k for k, _ in sorted(d.items(), key=lambda kv: kv[1], reverse=True)]
                 for cle, d in etat_monitor["hotes"].items()}
        brut = list(etat_monitor["brut"])[-60:]
    return {"actif": etat_monitor["actif"], "hotes": hotes, "brut": brut}
