#!/usr/bin/env python3
"""Stream WPA candidates mutated from custom-name seed words (Raton ESSID stage).

Reads one seed word per line (path given as argv[1]) and prints candidates to
stdout, one per line. Every candidate is kept inside the WPA-friendly 8..15
character window, and affix lengths adapt to each word so short names are padded
up to 8 and long names are not pushed past 15.

Candidates are emitted layer by layer, from the highest-yield mutations to the
most exotic ones, so that an upstream line limit always keeps the best first:
  1. case form + numeric / year / common suffix
  2. symbol suffix, prefixes, and both-sided wraps
  3. leet substitutions crossed with short suffixes only
  4. uppercase forms and word concatenations to reach the longer lengths
"""
import sys

MIN_LEN = 8
MAX_LEN = 15

SYMBOLS = ["!", "@", "#", "$", "*", "?", "."]
PREFIX_SYMBOLS = ["!", "@", "#", "$"]
YEARS = [str(y) for y in range(1980, 2027)]
COMMON = ["123", "1234", "12345", "123456", "1234567", "12345678",
          "00", "000", "0000", "007", "69", "666", "777", "321"]

# Leet tables used only in the leet layer, crossed with short affixes.
LEET_TABLES = [
    str.maketrans({"a": "@"}),
    str.maketrans({"a": "4"}),
    str.maketrans({"o": "0"}),
    str.maketrans({"i": "1"}),
    str.maketrans({"e": "3"}),
    str.maketrans({"a": "@", "o": "0"}),
    str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0"}),
    str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"}),
]


def num_strings(min_len, max_len, max_digits):
    """Fixed-length digit strings whose length fits within [min_len, max_len]."""
    lo = max(1, min_len)
    hi = min(max_digits, max_len)
    for d in range(lo, hi + 1):
        for n in range(10 ** d):
            yield str(n).zfill(d)


def capitalize(word):
    return word[:1].upper() + word[1:]


def generate(words):
    seen = set()

    def ok(candidate):
        if MIN_LEN <= len(candidate) <= MAX_LEN and candidate not in seen:
            seen.add(candidate)
            return True
        return False

    # Unique lowercase stems, in input order.
    stems = []
    for word in words:
        low = word.lower()
        if low and low not in stems:
            stems.append(low)

    # Case forms used by the first layers: lowercase and Capitalized.
    bases = []
    for stem in stems:
        for base in (stem, capitalize(stem)):
            if base not in bases:
                bases.append(base)

    # Layer 1: case form + numeric / year / common suffix.
    for base in bases:
        if ok(base):
            yield base
        room = MAX_LEN - len(base)
        need = MIN_LEN - len(base)
        for suffix in num_strings(need, room, 4):
            cand = base + suffix
            if ok(cand):
                yield cand
        for suffix in YEARS + COMMON:
            cand = base + suffix
            if ok(cand):
                yield cand

    # Layer 2: symbol suffix, prefixes, both-sided wraps.
    for base in bases:
        for sym in SYMBOLS:
            cand = base + sym
            if ok(cand):
                yield cand
        for pre in list("0123456789") + PREFIX_SYMBOLS + ["12", "123", "20", "19"]:
            cand = pre + base
            if ok(cand):
                yield cand
        for pre in YEARS:
            for suffix in SYMBOLS + ["1", "12", "123"]:
                cand = pre + base + suffix
                if ok(cand):
                    yield cand

    # Layer 3: leet substitutions, crossed with short suffixes only.
    for base in bases:
        for table in LEET_TABLES:
            leet = base.translate(table)
            if leet == base:
                continue
            if ok(leet):
                yield leet
            for suffix in num_strings(MIN_LEN - len(leet), MAX_LEN - len(leet), 2):
                cand = leet + suffix
                if ok(cand):
                    yield cand
            for sym in SYMBOLS:
                cand = leet + sym
                if ok(cand):
                    yield cand

    # Layer 4: uppercase forms and concatenations to reach the longer lengths.
    for stem in stems:
        upper = stem.upper()
        if ok(upper):
            yield upper
        for suffix in num_strings(MIN_LEN - len(upper), MAX_LEN - len(upper), 4):
            cand = upper + suffix
            if ok(cand):
                yield cand
    for first in stems:
        for second in stems:
            for cand in (first + second, capitalize(first) + capitalize(second)):
                if ok(cand):
                    yield cand
    for base in bases:
        for suffix in num_strings(max(5, MIN_LEN - len(base)), MAX_LEN - len(base), 6):
            cand = base + suffix
            if ok(cand):
                yield cand


def main(path):
    with open(path, encoding="utf-8", errors="ignore") as handle:
        words = [line.strip() for line in handle if line.strip()]
    write = sys.stdout.write
    for candidate in generate(words):
        write(candidate + "\n")


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except (BrokenPipeError, IndexError):
        pass
