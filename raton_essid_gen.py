#!/usr/bin/env python3
"""Stream WPA candidates mutated from custom-name seed words (Raton stage 2)."""
import sys

LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"})
SUFFIXES = ["", "!", "@", "#", "123", "1234", "12345",
            "2020", "2021", "2022", "2023", "2024", "2025", "2026",
            "00", "01", "007", "69"]

def variantes(mot):
    formes = {mot, mot.lower(), mot.upper(), mot.capitalize(),
              mot.translate(LEET), mot.lower().translate(LEET)}
    for base in list(formes):
        yield base
        yield base + base
        for s in SUFFIXES:
            yield base + s
        for n in range(10000):
            yield base + str(n)

def main(seed):
    with open(seed, encoding="utf-8", errors="ignore") as f:
        mots = [l.strip() for l in f if l.strip()]
    vus = set()
    for mot in mots:
        for c in variantes(mot):
            if 8 <= len(c) <= 63 and c not in vus:
                vus.add(c)
                sys.stdout.write(c + "\n")

if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except (BrokenPipeError, IndexError):
        pass
