"""Vigie monitoring engine: MITM (bettercap) to route the traffic through the Pi,
+ SNI/DNS capture via tshark (the Wireshark engine), which reads the SNI of plain
TLS (TCP/443) AND of QUIC (UDP/443, HTTP/3) — which bettercap did not do.
Aggregated per device, key = source IP (given directly by tshark).

The sudo script /usr/local/bin/fennec-monitor starts bettercap (arp.spoof) then
tshark with tab-separated "fields" output:  ip.src <TAB> sni <TAB> dns
Only one domain column is filled per line; we take the first one.
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
    "hotes": {},                 # ip -> OrderedDict(domain -> ts)
    "brut": deque(maxlen=250),   # last raw lines (debugging)
}

_proc = None
_thread = None
_verrou = threading.Lock()

_RE_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IGNORER_DOM = re.compile(r"(\.lan|\.local|\.arpa|\.home|\.internal)$", re.I)
_RE_PRIVE = re.compile(r"^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|224\.|0\.)")
_cache_rdns = {}
_vu_dst = {}   # (src, dst) -> last ts, to avoid reprocessing the QUIC flow


def _est_prive(ip):
    return bool(_RE_PRIVE.match(ip))


def _rdns(ip):
    """Reverse DNS of a destination IP (cached), else the raw IP."""
    if ip in _cache_rdns:
        return _cache_rdns[ip]
    nom = None
    try:
        nom = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
    except Exception:
        nom = None
    val = nom if (nom and not _IGNORER_DOM.search(nom)) else ip
    _cache_rdns[ip] = val
    return val


def _noter(ip, domaine):
    with _verrou:
        d = etat_monitor["hotes"].setdefault(ip, OrderedDict())
        d[domaine] = time.time()
        while len(d) > 60:
            d.popitem(last=False)


def _traiter(ligne):
    # tshark fields: ip.src <TAB> ip.dst <TAB> sni <TAB> dns
    champs = ligne.rstrip("\n").split("\t")
    while len(champs) < 4:
        champs.append("")
    src = champs[0].strip()
    dst = champs[1].strip()
    sni = champs[2].strip().split(",")[0].strip()
    dns = champs[3].strip().split(",")[0].strip()
    # The source must be a local device (filters out server->client reply packets)
    if not _RE_IP.match(src) or not _est_prive(src):
        return
    dom = (sni or dns).lower().rstrip(".")
    if dom:
        if _RE_IP.match(dom) or _IGNORER_DOM.search(dom):
            return
        _noter(src, dom)
        return
    # Neither SNI nor DNS (encrypted handshake, e.g. QUIC/ECH): record the destination.
    if not _RE_IP.match(dst) or _est_prive(dst):
        return
    cle = (src, dst)
    now = time.time()
    if now - _vu_dst.get(cle, 0) < 3:   # anti-flood: once / 3s per (src,dst)
        return
    _vu_dst[cle] = now
    if len(_vu_dst) > 5000:
        _vu_dst.clear()
    _noter(src, _rdns(dst))


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
    """Start the script (bettercap + tshark) and the reader thread."""
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
    """Stop bettercap + tshark cleanly (the whole process group)."""
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
    """Domains + last timestamp for one or more keys (IP)."""
    out = {}
    with _verrou:
        for cle in cles:
            for dom, ts in etat_monitor["hotes"].get(cle, {}).items():
                if dom not in out or ts > out[dom]:
                    out[dom] = ts
    return out


def instantane():
    """JSON-able view: active + domains per device + last raw lines."""
    with _verrou:
        hotes = {ip: [k for k, _ in sorted(d.items(), key=lambda kv: kv[1], reverse=True)]
                 for ip, d in etat_monitor["hotes"].items()}
        brut = list(etat_monitor["brut"])[-60:]
    return {"actif": etat_monitor["actif"], "hotes": hotes, "brut": brut}
