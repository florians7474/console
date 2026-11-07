"""Vigie monitoring engine. The sudo script /usr/local/bin/fennec-monitor starts
bettercap (arp.spoof) to route the subnet through the Pi, then two capture
sources whose lines are merged on the same stdout:

  - dnsmasq, acting as the DNS resolver: every port-53 query transiting the Pi
    is redirected to it, so it logs the full domain name per device, even for a
    device pointed at a public resolver. Lines:  query[A] <domain> from <ip>
  - tshark: SNI of plain TLS (TCP/443) AND of QUIC (UDP/443, HTTP/3), the
    destination of encrypted handshakes, and VPN control packets (WireGuard,
    OpenVPN, IPsec/IKEv2) used to flag a tunnelling device by protocol.
    Tab fields:  ip.src  ip.dst  sni  dns  protocol

Aggregated per device, key = source IP (the device IP in both sources).
"""
import os
import re
import socket
import signal
import subprocess
import threading
import time
from collections import deque, OrderedDict

monitor_state = {
    "actif": False,
    "depuis": None,
    "hotes": {},                 # ip -> OrderedDict(domain -> ts)
    "brut": deque(maxlen=250),   # last raw lines (debugging)
}

_proc = None
_thread = None
_lock = threading.Lock()
_force_dns = False   # "Force DNS": DoT/DoH blocked to flush out hardened devices

_RE_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IGNORER_DOM = re.compile(r"(\.lan|\.local|\.arpa|\.home|\.internal)$", re.I)
# dnsmasq query log line: "query[A] example.com from 192.168.1.42"
_RE_DNSMASQ = re.compile(
    r"query\[[^\]]+\]\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})")
# tshark protocol-column name -> VPN label (for detection)
_VPN_PROTO = {
    "wireguard": "WireGuard",
    "openvpn": "OpenVPN",
    "isakmp": "IPsec/IKEv2",
}
_RE_PRIVE = re.compile(r"^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|224\.|0\.)")
_cache_rdns = {}
_seen_dst = {}   # (src, dst) -> last ts, to avoid reprocessing the QUIC flow
_vpn = {}      # device ip -> {"type", "endpoint", "ip", "ts"} (tunnel detected)


def _is_private(ip):
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


def _record(ip, domaine):
    with _lock:
        d = monitor_state["hotes"].setdefault(ip, OrderedDict())
        d[domaine] = time.time()
        while len(d) > 60:
            d.popitem(last=False)


def _record_vpn(ip, type_, dst):
    with _lock:
        _vpn[ip] = {"type": type_, "endpoint": _rdns(dst), "ip": dst,
                    "ts": time.time()}


def _process(ligne):
    # dnsmasq query log: "query[TYPE] <domain> from <device-ip>"
    m = _RE_DNSMASQ.search(ligne)
    if m:
        dom = m.group(1).lower().rstrip(".")
        src = m.group(2).strip()
        if (_is_private(src) and dom and not _RE_IP.match(dom)
                and not _IGNORER_DOM.search(dom)):
            _record(src, dom)
        return
    # tshark fields: ip.src <TAB> ip.dst <TAB> sni <TAB> dns <TAB> protocol
    fields = ligne.rstrip("\n").split("\t")
    while len(fields) < 5:
        fields.append("")
    src = fields[0].strip()
    dst = fields[1].strip()
    sni = fields[2].strip().split(",")[0].strip()
    dns = fields[3].strip().split(",")[0].strip()
    proto = fields[4].strip().lower()
    # The source must be a local device (filters out server->client reply packets)
    if not _RE_IP.match(src) or not _is_private(src):
        return
    # VPN control packet (WireGuard / OpenVPN / IPsec-IKEv2): the device is
    # tunneling to dst. Record it and stop — do not log the endpoint as a domain.
    vpn = _VPN_PROTO.get(proto)
    if vpn and _RE_IP.match(dst) and not _is_private(dst):
        _record_vpn(src, vpn, dst)
        return
    dom = (sni or dns).lower().rstrip(".")
    if dom:
        if _RE_IP.match(dom) or _IGNORER_DOM.search(dom):
            return
        _record(src, dom)
        return
    # Neither SNI nor DNS (encrypted handshake, e.g. QUIC/ECH): record the destination.
    if not _RE_IP.match(dst) or _is_private(dst):
        return
    cle = (src, dst)
    now = time.time()
    if now - _seen_dst.get(cle, 0) < 3:   # anti-flood: once / 3s per (src,dst)
        return
    _seen_dst[cle] = now
    if len(_seen_dst) > 5000:
        _seen_dst.clear()
    _record(src, _rdns(dst))


def _read(proc):
    for ligne in iter(proc.stdout.readline, ""):
        ligne = ligne.rstrip("\n")
        if not ligne:
            continue
        monitor_state["brut"].append(ligne)
        try:
            _process(ligne)
        except Exception:
            pass


def start(prefix=None):
    """Start the script (bettercap + tshark) and the reader thread."""
    global _proc, _thread
    if monitor_state["actif"]:
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
    global _force_dns
    _force_dns = False
    with _lock:
        monitor_state["actif"] = True
        monitor_state["depuis"] = time.time()
        monitor_state["hotes"] = {}
        _vpn.clear()
        monitor_state["brut"].clear()
    _thread = threading.Thread(target=_read, args=(_proc,), daemon=True)
    _thread.start()
    return True


def stop():
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
    global _force_dns
    _force_dns = False   # the monitor script clears the block when it exits
    with _lock:
        monitor_state["actif"] = False


def forcer_dns(actif):
    """Toggle 'Force DNS' (block DoT/DoH) via the sudo helper. Only meaningful
    while the Watch is running (the block sits on the MITM-forwarded traffic)."""
    global _force_dns
    if not monitor_state["actif"]:
        return False
    try:
        subprocess.run(
            ["sudo", "-n", "/usr/local/bin/fennec-dns-force",
             "on" if actif else "off"],
            timeout=10,
        )
        _force_dns = bool(actif)
    except Exception:
        pass
    return _force_dns


def vpn_info(cles):
    """VPN tunnel detected for one of these keys (device IP), else None."""
    with _lock:
        for cle in cles:
            v = _vpn.get(cle)
            if v:
                return {"type": v["type"], "endpoint": v["endpoint"], "ip": v["ip"]}
    return None


def timestamps(cles):
    """Domains + last timestamp for one or more keys (IP)."""
    out = {}
    with _lock:
        for cle in cles:
            for dom, ts in monitor_state["hotes"].get(cle, {}).items():
                if dom not in out or ts > out[dom]:
                    out[dom] = ts
    return out


def snapshot():
    """JSON-able view: active + domains per device + last raw lines."""
    with _lock:
        hotes = {ip: [k for k, _ in sorted(d.items(), key=lambda kv: kv[1], reverse=True)]
                 for ip, d in monitor_state["hotes"].items()}
        brut = list(monitor_state["brut"])[-60:]
    return {"actif": monitor_state["actif"], "force": _force_dns,
            "hotes": hotes, "brut": brut}
