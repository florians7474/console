#!/usr/bin/env python3
"""Raton cracking engine — stage-based WPA cracking on the Pi (aircrack-ng)."""
import os
import re
import subprocess
import threading
import time

WORDLISTS = {
    "rockyou": "/usr/share/wordlists/rockyou.txt",
}

# Live state of the current/last job, read by the web UI.
etat_cassage = {
    "actif": False,
    "bssid": None,
    "reseau": None,
    "etape": None,
    "etape_num": 0,
    "etape_total": 1,
    "testes": 0,
    "total": 0,
    "vitesse": 0.0,
    "candidat": "",
    "trouve": False,
    "cle": None,
    "fini": False,
    "message": "",
}

_verrou = threading.Lock()
_proc = None

RE_TESTES = re.compile(r"(\d+)/(\d+)\s+keys tested\s+\(([\d.]+)\s*k/s\)")
RE_CANDIDAT = re.compile(r"Current passphrase:\s*(.*\S)")
RE_TROUVE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")


def _reset(bssid, reseau):
    etat_cassage.update({
        "actif": True, "bssid": bssid, "reseau": reseau,
        "etape": None, "etape_num": 0, "etape_total": 1,
        "testes": 0, "total": 0, "vitesse": 0.0, "candidat": "",
        "trouve": False, "cle": None, "fini": False, "message": "",
    })


def lancer(pcap, bssid, reseau="", wordlist=WORDLISTS["rockyou"]):
    """Start a crack job in the background. Returns immediately."""
    _reset(bssid, reseau)
    t = threading.Thread(target=_run, args=(pcap, bssid, reseau, wordlist), daemon=True)
    t.start()


def _run(pcap, bssid, reseau, wordlist):
    global _proc
    keyfile = "/tmp/raton_found.key"
    try:
        if os.path.exists(keyfile):
            os.remove(keyfile)
    except OSError:
        pass

    etat_cassage["etape"] = "rockyou"
    etat_cassage["etape_num"] = 1

    cmd = ["aircrack-ng", "-w", wordlist, "-l", keyfile, "-b", bssid, pcap]
    try:
        _proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, bufsize=1,
        )
    except FileNotFoundError:
        etat_cassage.update({"actif": False, "fini": True, "message": "aircrack-ng not found"})
        return

    buf = ""
    while True:
        ch = _proc.stdout.read(1)
        if ch == "":
            break
        buf += ch
        if ch in ("\r", "\n"):
            _parser(buf)
            buf = ""
    _proc.wait()

    cle = None
    try:
        with open(keyfile) as f:
            cle = f.read().strip()
    except OSError:
        pass

    with _verrou:
        etat_cassage["actif"] = False
        etat_cassage["fini"] = True
        if cle:
            etat_cassage["trouve"] = True
            etat_cassage["cle"] = cle
            etat_cassage["message"] = "Cracked"
        else:
            etat_cassage["message"] = "Exhausted"


def _parser(ligne):
    m = RE_TESTES.search(ligne)
    if m:
        with _verrou:
            etat_cassage["testes"] = int(m.group(1))
            etat_cassage["total"] = int(m.group(2))
            etat_cassage["vitesse"] = float(m.group(3))
    m = RE_CANDIDAT.search(ligne)
    if m:
        with _verrou:
            etat_cassage["candidat"] = m.group(1).strip()
    m = RE_TROUVE.search(ligne)
    if m:
        with _verrou:
            etat_cassage["trouve"] = True
            etat_cassage["cle"] = m.group(1)


def arreter():
    global _proc
    if _proc and _proc.poll() is None:
        _proc.terminate()
    etat_cassage["actif"] = False
    etat_cassage["fini"] = True
    etat_cassage["message"] = "Stopped"


if __name__ == "__main__":
    import sys
    pcap = sys.argv[1]
    bssid = sys.argv[2]
    wl = sys.argv[3] if len(sys.argv) > 3 else WORDLISTS["rockyou"]
    lancer(pcap, bssid, wordlist=wl)
    while not etat_cassage["fini"]:
        e = etat_cassage
        print(f"\r[{e['etape']}] {e['testes']}/{e['total']} {e['vitesse']} k/s  try={e['candidat']}   ", end="", flush=True)
        time.sleep(0.5)
    print()
    print("RESULT:", etat_cassage["message"], "KEY=", etat_cassage["cle"])
