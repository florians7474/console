"""Moteur de monitoring Vigie : MITM (bettercap) + sniff du trafic, agrégé
par appareil (quels domaines chaque IP contacte). Lancé via le script sudo
fennec-monitor. Le parseur des lignes bettercap est volontairement tolérant
et expose aussi les dernières lignes brutes, pour pouvoir l'ajuster sur le Pi.
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
    "hotes": {},          # ip -> OrderedDict(domaine -> timestamp)
    "brut": deque(maxlen=250),  # dernières lignes brutes (pour réglage)
}

_proc = None
_thread = None
_verrou = threading.Lock()

# Un domaine : au moins deux labels, un TLD alphabétique de 2+ lettres.
_RE_DOM = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b", re.I)
_RE_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# On ne garde que les lignes de sniff qui portent un domaine utile.
_INDICES = ("sniff.dns", "sniff.https", "sniff.http", "sniff.mdns", "dns", "https")
_IGNORER_DOM = re.compile(r"(in-addr\.arpa|\.local$|\.arpa$)", re.I)
_RE_TAGS = re.compile(r"\[[^\]]*\]")   # balises bettercap entre crochets
# Faux TLD issus du vocabulaire bettercap (pour éviter de prendre une étiquette pour un domaine).
_FAUX_TLD = {"dns", "https", "http", "mdns", "tcp", "udp", "arp", "net", "sniff",
             "log", "sys", "inf", "war", "err", "dbg", "local"}


def _est_locale(ip, prefixe):
    return prefixe and ip.startswith(prefixe)


def _noter(ip, domaine):
    domaine = domaine.lower().strip(".")
    if _IGNORER_DOM.search(domaine):
        return
    with _verrou:
        d = etat_monitor["hotes"].setdefault(ip, OrderedDict())
        d[domaine] = time.time()
        # garde les 40 derniers domaines par hôte
        while len(d) > 40:
            d.popitem(last=False)


def _lire(proc, prefixe):
    for ligne in iter(proc.stdout.readline, ""):
        ligne = ligne.rstrip("\n")
        if not ligne:
            continue
        etat_monitor["brut"].append(ligne)
        bas = ligne.lower()
        if not any(k in bas for k in _INDICES):
            continue
        propre = _RE_TAGS.sub(" ", ligne)   # retire les balises [net.sniff.dns] etc.
        ips = _RE_IP.findall(propre)
        src = next((ip for ip in ips if _est_locale(ip, prefixe)), ips[0] if ips else None)
        if not src:
            continue
        for dom in _RE_DOM.findall(propre):
            if _RE_IP.fullmatch(dom):
                continue
            if dom.rsplit(".", 1)[-1].lower() in _FAUX_TLD:
                continue
            _noter(src, dom)


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


def domaines(ip):
    """Domaines contactés par une IP, du plus récent au plus ancien."""
    with _verrou:
        d = etat_monitor["hotes"].get(ip, {})
        items = sorted(d.items(), key=lambda kv: kv[1], reverse=True)
    return [dom for dom, _ in items]


def instantane():
    """Vue JSON-able : actif + domaines par hôte + dernières lignes brutes."""
    with _verrou:
        hotes = {ip: [k for k, _ in sorted(d.items(), key=lambda kv: kv[1], reverse=True)]
                 for ip, d in etat_monitor["hotes"].items()}
        brut = list(etat_monitor["brut"])[-60:]
    return {"actif": etat_monitor["actif"], "hotes": hotes, "brut": brut}
