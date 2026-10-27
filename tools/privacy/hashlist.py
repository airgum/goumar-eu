"""Build/extend the salted hash list from raw names on stdin.

  hashlist.py build --salt-file PATH --out PATH [--proof PATH] [--merge-into EXISTING] < names.txt

Prints counts only. Never prints a name or a hash.
Dictionary drop: a single-token n-gram is dropped when its lowercase surface
form has wordfreq zipf frequency >= ZIPF_THRESHOLD in en, ru or es, or when its
stem is shorter than MIN_STEM. Multi-token n-grams are never dropped.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Set

import config
import normalize

ZIPF_THRESHOLD = 3.5   # ~3 occurrences per million words
LANGS = ("en", "ru", "es")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ProofError(Exception):
    pass


def is_dictionary_word(word: str) -> bool:
    from wordfreq import zipf_frequency  # lazy: hook/scrub do not need it
    return any(zipf_frequency(word, lang) >= ZIPF_THRESHOLD for lang in LANGS)


def _ngram_entries(line: str):
    """Yield (key, unigram_surface_or_None) for a raw name."""
    tokens = normalize.tokenize(line)
    for key, i, j in normalize.ngrams(tokens):
        yield key, (tokens[i].lower if i == j else None), (i == j and len(key) < normalize.MIN_STEM)


def proof_hashes(lines: Iterable[str], salt: bytes) -> Set[str]:
    out: Set[str] = set()
    for line in lines:
        line = line.strip()
        if _HEX64.match(line):
            out.add(line)
        elif line:
            for key, _, _ in _ngram_entries(line):
                out.add(config.hash_key(salt, key))
    return out


def build_hashes(names: Iterable[str], salt: bytes, proof: Optional[Iterable[str]] = None,
                 existing: Optional[Set[str]] = None):
    """Return (hashes_after_merge, counts). Raises ProofError (message has a count only)."""
    received = 0
    dropped = 0
    kept: Set[str] = set()
    dropped_hashes: Set[str] = set()
    seen = set()
    for line in names:
        if not line.strip():
            continue
        received += 1
        for key, surface, too_short in _ngram_entries(line):
            if key in seen:
                continue
            seen.add(key)
            h = config.hash_key(salt, key)
            if surface is not None and (too_short or is_dictionary_word(surface)):
                dropped += 1
                dropped_hashes.add(h)
            else:
                kept.add(h)
    if proof is not None:
        clash = dropped_hashes & proof_hashes(proof, salt)
        if clash:
            raise ProofError("%d dropped dictionary word(s) match proof-set entries" % len(clash))
    kept.add(config.canary_hash(salt))
    total = kept | (existing or set())
    return total, {"received": received, "dropped_dictionary": dropped,
                   "kept": len(kept), "total": len(total)}


def _main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="hashlist.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--salt-file", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--proof")
    b.add_argument("--merge-into")
    args = ap.parse_args(argv)
    try:
        salt = Path(args.salt_file).read_text(encoding="utf-8").strip().encode("utf-8")
        if not salt:
            raise config.ConfigError("salt is empty")
        existing = None
        if args.merge_into:
            try:
                existing = config.parse_hashes(Path(args.merge_into).read_text(encoding="utf-8"))
            except OSError:
                raise config.ConfigError("merge-into file missing or unreadable")
        proof = None
        if args.proof:
            try:
                proof = Path(args.proof).read_text(encoding="utf-8").splitlines()
            except OSError:
                raise config.ConfigError("proof file missing or unreadable")
        total, counts = build_hashes(sys.stdin.read().splitlines(), salt, proof, existing)
    except OSError:
        print("hashlist: salt file missing or unreadable", file=sys.stderr)
        return 2
    except config.ConfigError as e:
        print("hashlist: %s" % e, file=sys.stderr)
        return 2
    except ProofError as e:
        print("hashlist: STOP: %s" % e, file=sys.stderr)
        return 3
    out = Path(args.out)
    out.write_text("\n".join(sorted(total)) + "\n", encoding="utf-8")
    os.chmod(out, 0o600)
    print("received=%(received)d dropped_dictionary=%(dropped_dictionary)d kept=%(kept)d total=%(total)d" % counts)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
