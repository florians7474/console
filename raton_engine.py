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
crack_state = {
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
    "enregistree": False,
    "robustesse": None,
    "sans_handshake": False,
}

_lock = threading.Lock()
_proc = None

RE_TESTES = re.compile(r"(\d+)/(\d+)\s+keys tested\s+\(([\d.]+)\s*k/s\)")
RE_CANDIDAT = re.compile(r"Current passphrase:\s*(.*\S)")
RE_TROUVE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")
RE_TESTES_FLUX = re.compile(r"(\d+)\s+keys tested\s+\(([\d.]+)\s*k/s\)")


def _reset(bssid, reseau):
    crack_state.update({
        "actif": True, "bssid": bssid, "reseau": reseau,
        "etape": None, "etape_num": 0, "etape_total": 1,
        "testes": 0, "total": 0, "vitesse": 0.0, "candidat": "",
        "trouve": False, "cle": None, "fini": False, "message": "",
        "journal": [],
        "enregistree": False,
        "sans_handshake": False,
    })


def lancer(pcap, bssid, reseau="", wordlist=WORDLISTS["rockyou"]):
    """Start a crack job in the background. Returns immediately."""
    _reset(bssid, reseau)
    t = threading.Thread(target=_run, args=(pcap, bssid, reseau, wordlist), daemon=True)
    t.start()

def generate_keyboard(fichier):
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

def generate_dates(fichier, an_debut=1950, an_fin=2025):
    """Stage: generate all DDMMYYYY dates (8 digits) as WPA candidates."""
    jours_par_mois = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    with open(fichier, "w") as f:
        for annee in range(an_debut, an_fin + 1):
            for mois in range(1, 13):
                for jour in range(1, jours_par_mois[mois - 1] + 1):
                    f.write("%02d%02d%04d\n" % (jour, mois, annee))
                    f.write("%04d%02d%02d\n" % (annee, mois, jour))
    return fichier

_profils_cache = None

def _load_profiles():
    """Load the box-profile knowledge base (tiny JSON next to this engine)."""
    global _profils_cache
    if _profils_cache is not None:
        return _profils_cache
    import json
    chemin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profils_box.json")
    try:
        with open(chemin, encoding="utf-8") as f:
            _profils_cache = json.load(f).get("profils", [])
    except (OSError, ValueError):
        _profils_cache = []
    return _profils_cache

def profile_for_essid(essid):
    """Return the matching box profile for an ESSID, or None."""
    if not essid:
        return None
    for p in _load_profiles():
        if essid.startswith(p.get("prefix", "\0")):
            return p
    return None

def factory_keys(essid, bssid):
    """Stage 1: targeted factory keys = box-profile routing + routerkeygen-cli."""
    profil = profile_for_essid(essid)
    # Known non-target (community hotspot, etc.): skip the whole stage.
    if profil and profil.get("algo") == "ignore":
        return []
    try:
        out = subprocess.run(
            ["routerkeygen-cli", "-q", "-s", essid, "-m", bssid],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    cles, vus = [], set()
    for ligne in out.stdout.splitlines():
        c = ligne.strip()
        if 8 <= len(c) <= 63 and " " not in c and c not in vus:
            vus.add(c)
            cles.append(c)
    return cles

def essid_words(essid):
    """Extract seed words from a *custom* network name.
    Returns [] for generic/box names (already handled by the factory stage)."""
    if not essid:
        return []
    if profile_for_essid(essid):      # known box prefix -> generic name, skip
        return []
    mots = set()
    nu = essid.strip()
    compact = re.sub(r"[^A-Za-z0-9]", "", nu)
    for v in (nu, compact):
        if v:
            mots.add(v)
            mots.add(v.lower())
    for t in re.split(r"[^A-Za-z]+", nu):
        if len(t) >= 3:
            mots.add(t)
            mots.add(t.lower())
            mots.add(t.capitalize())
    return sorted(mots)

def generate_essid(fichier, essid):
    """Stage 2 seed file: custom-name words (John rules mutate them later)."""
    mots = essid_words(essid)
    with open(fichier, "w") as f:
        for m in mots:
            f.write(m + "\n")
    return len(mots)

STAGES = [
    {"nom": "factory default keys", "type": "constructeur"},
    {"nom": "ESSID profiling (custom name)", "type": "essid"},
    {"nom": "real cracked keys (probable-wpa)", "type": "wordlist", "fichier": "/usr/share/wordlists/probable-wpa-top4800.txt"},
    {"nom": "birth dates (DDMMYYYY/YYYYMMDD)", "type": "genere", "generateur": generate_dates},
    {"nom": "10k common passwords", "type": "wordlist", "fichier": "/usr/share/wordlists/10k-common.txt"},
    {"nom": "keyboard patterns", "type": "genere", "generateur": generate_keyboard},
    {"nom": "common + mutation rules", "type": "regles", "fichier": "/usr/share/wordlists/10k-common.txt"},
    {"nom": "John incremental (1h)", "type": "temps", "source": "john_inc"},
    {"nom": "rockyou random (1h)", "type": "temps", "source": "rockyou_shuf"},
]

def a_un_handshake(pcap, bssid=None):
    """True if the capture holds at least one WPA handshake."""
    try:
        r = subprocess.run(
            ["aircrack-ng", pcap],
            capture_output=True, text=True, timeout=30,
            stdin=subprocess.DEVNULL,
        )
    except Exception:
        return True   # en cas de doute, on laisse Raton tourner
    for m in re.finditer(r"WPA \((\d+)\s+handshake", r.stdout or ""):
        if int(m.group(1)) > 0:
            return True
    return False


def _run(pcap, bssid, reseau, wordlist):
    global _proc
    keyfile = "/tmp/raton_found.key"
    crack_state["etape_total"] = len(STAGES)

    if not a_un_handshake(pcap, bssid):
        with _lock:
            crack_state["actif"] = False
            crack_state["fini"] = True
            crack_state["sans_handshake"] = True
            crack_state["message"] = "No handshake"
        return

    for i, etage in enumerate(STAGES, start=1):
        if not crack_state["actif"]:
            break

        # Prepare this stage's wordlist / source
        if etage["type"] == "constructeur":
            cles = factory_keys(reseau, bssid)
            if not cles:
                with _lock:
                    crack_state["journal"].append({"num": i, "nom": etage["nom"], "resultat": "skipped"})
                continue
            wl = "/tmp/raton_stage_const.txt"
            with open(wl, "w") as f:
                f.write("\n".join(cles) + "\n")
        elif etage["type"] == "essid":
            seed = "/tmp/raton_stage_essid.txt"
            n = generate_essid(seed, reseau)
            if n == 0:
                with _lock:
                    crack_state["journal"].append({"num": i, "nom": etage["nom"], "resultat": "skipped"})
                continue
            gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), "raton_essid_gen.py")
            wl = "/dev/shm/raton_essid.txt"
            with open(wl, "w") as f:
                p1 = subprocess.Popen(["python3", gen, seed],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                subprocess.run(["head", "-n", "300000"], stdin=p1.stdout, stdout=f)
                p1.stdout.close()
                p1.wait()
        elif etage["type"] == "genere":
            wl = "/tmp/raton_stage_gen.txt"
            etage["generateur"](wl)
        elif etage["type"] == "regles":
            wl = "PIPE_JOHN"
            dico_regles = etage["fichier"]
        elif etage["type"] == "temps":
            wl = "TEMPS"
        else:
            base = etage["fichier"]
            wl = "/dev/shm/raton_wl.txt"
            with open(wl, "w") as f:
                subprocess.run(["awk", "length>=8 && length<=63", base], stdout=f)

        est_temps = (etage["type"] == "temps")
        with _lock:
            crack_state["etape"] = etage["nom"]
            crack_state["etape_num"] = i
            crack_state["testes"] = 0
            crack_state["total"] = 0
            crack_state["candidat"] = ""
            crack_state["flux"] = (etage["type"] == "regles")
            crack_state["jauge_temps"] = est_temps
            crack_state["temps_total"] = 3600 if est_temps else 0
            crack_state["temps_ecoule"] = 0

        try:
            if os.path.exists(keyfile):
                os.remove(keyfile)
        except OSError:
            pass

        _john = None
        _head = None
        if wl == "PIPE_JOHN":
            _john = subprocess.Popen(
                ["john", "--stdout", "--rules", "--wordlist=" + dico_regles],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            _head = subprocess.Popen(
                ["awk", "length>=8 && length<=63"],
                stdin=_john.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            _john.stdout.close()
            aircrack_stdin = _head.stdout
            cmd = ["aircrack-ng", "-w", "-", "-l", keyfile, "-b", bssid, pcap]
        elif wl == "PIPE_ESSID":
            gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), "raton_essid_gen.py")
            _john = subprocess.Popen(
                ["python3", gen, dico_regles],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            _head = subprocess.Popen(
                ["head", "-n", "100000"],
                stdin=_john.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            _john.stdout.close()
            aircrack_stdin = _head.stdout
            cmd = ["aircrack-ng", "-w", "-", "-l", keyfile, "-b", bssid, pcap]
        elif wl == "TEMPS":
            if etage["source"] == "john_inc":
                src = ["john", "--stdout", "--incremental=ASCII"]
            else:
                src = ["shuf", WORDLISTS["rockyou"]]
            _john = subprocess.Popen(src, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            _head = subprocess.Popen(
                ["awk", "length>=8 && length<=63"],
                stdin=_john.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            _john.stdout.close()
            aircrack_stdin = _head.stdout
            cmd = ["aircrack-ng", "-w", "-", "-l", keyfile, "-b", bssid, pcap]
        else:
            cmd = ["aircrack-ng", "-w", wl, "-l", keyfile, "-b", bssid, pcap]
            aircrack_stdin = None

        try:
            _proc = subprocess.Popen(
                cmd, stdin=aircrack_stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding="utf-8", errors="replace", bufsize=1,
            )
        except FileNotFoundError:
            crack_state.update({"actif": False, "fini": True, "message": "aircrack-ng not found"})
            return

        if est_temps:
            fin = time.time() + 3600
            def _horloge(p, src_proc, fin):
                while p.poll() is None:
                    reste = fin - time.time()
                    with _lock:
                        crack_state["temps_ecoule"] = max(0, min(3600, int(3600 - reste)))
                    if reste <= 0:
                        for q in (p, src_proc):
                            try:
                                q.terminate()
                            except Exception:
                                pass
                        break
                    time.sleep(1)
            threading.Thread(target=_horloge, args=(_proc, _john, fin), daemon=True).start()

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
        if _john is not None:
            try:
                _john.terminate()
            except Exception:
                pass
        if _head is not None:
            try:
                _head.terminate()
            except Exception:
                pass

        cle = None
        try:
            with open(keyfile) as f:
                cle = f.read().strip()
        except OSError:
            pass

        if cle:
            with _lock:
                crack_state["actif"] = False
                crack_state["fini"] = True
                crack_state["trouve"] = True
                crack_state["cle"] = cle
                crack_state["etape_echec"] = i
                crack_state["robustesse"] = _robustness_score(i, crack_state["etape_total"])
                crack_state["journal"].append({"num": i, "nom": etage["nom"], "resultat": "cracked"})
                crack_state["message"] = "Cracked"
            return

        with _lock:
            crack_state["journal"].append({"num": i, "nom": etage["nom"], "resultat": "not found"})

    with _lock:
        crack_state["actif"] = False
        crack_state["fini"] = True
        crack_state["robustesse"] = _robustness_score(None, crack_state["etape_total"])
        crack_state["message"] = "Exhausted"

def _robustness_score(etage_echec, total):
    """Robustness = the stage that cracked the key. Earlier stage = weaker key."""
    if etage_echec is None:
        return {
            "label": "Robust",
            "niveau": "ok",
            "detail": "Key resisted every offline cracking stage.",
        }
    libelles = {
        1: ("Critical",  "Factory-default / vendor-pattern key, recovered instantly."),
        2: ("Critical",  "Key derived from the network name itself."),
        3: ("Very weak", "Key found in a database of already-cracked WPA keys."),
        4: ("Very weak", "Key is a birth date."),
        5: ("Weak",      "Key found in a common-password list."),
        6: ("Weak",      "Key is a keyboard pattern."),
        7: ("Weak",      "Key is a simple variation of a common word."),
        8: ("Moderate",  "Key recovered by a short brute-force pass (under 1h)."),
        9: ("Moderate",  "Key found in the rockyou wordlist."),
    }
    label, detail = libelles.get(etage_echec, ("Weak", "Key recovered by an early stage."))
    return {
        "label": label,
        "niveau": "risque",
        "detail": detail,
        "etage": etage_echec,
        "total": total,
    }

def _parser(ligne):
    m = RE_TESTES.search(ligne)
    if m:
        with _lock:
            crack_state["testes"] = int(m.group(1))
            crack_state["total"] = int(m.group(2))
            crack_state["vitesse"] = float(m.group(3))
    m = RE_CANDIDAT.search(ligne)
    if m:
        with _lock:
            crack_state["candidat"] = m.group(1).strip()
    m = RE_TROUVE.search(ligne)
    if m:
        with _lock:
            crack_state["trouve"] = True
            crack_state["cle"] = m.group(1)

def stop():
    global _proc
    if _proc and _proc.poll() is None:
        _proc.terminate()
    crack_state["actif"] = False
    crack_state["fini"] = True
    crack_state["message"] = "Stopped"


if __name__ == "__main__":
    import sys
    pcap = sys.argv[1]
    bssid = sys.argv[2]
    wl = sys.argv[3] if len(sys.argv) > 3 else WORDLISTS["rockyou"]
    lancer(pcap, bssid, wordlist=wl)
    while not crack_state["fini"]:
        e = crack_state
        print(f"\r[{e['etape']}] {e['testes']}/{e['total']} {e['vitesse']} k/s  try={e['candidat']}   ", end="", flush=True)
        time.sleep(0.5)
    print()
    print("RESULT:", crack_state["message"], "KEY=", crack_state["cle"])
