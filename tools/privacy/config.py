"""Secret inputs: loading, validation, version. Fail-closed everywhere.

Each input comes from (first match wins):
  denylist   env GOUMAR_DENYLIST (content)          | env GOUMAR_DENYLIST_FILE | ~/.config/goumar/denylist.txt
  hashes     env GOUMAR_NAMES_HASHES_1..N (content, concatenated in order, stops at
             the first missing number) | env GOUMAR_NAMES_HASHES (content)
             | env GOUMAR_NAMES_HASHES_FILE | ~/.config/goumar/names.hashes
  salt       env GOUMAR_SALT (content)               | env GOUMAR_SALT_FILE     | ~/.config/goumar/salt
  version    env GOUMAR_VERSION_FILE | <repo root>/denylist.version
Any missing/empty input, any malformed hash line, a missing version file or a
version mismatch raises ConfigError (the tools exit with code 2).
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import List, NamedTuple, Optional, Set

import normalize

CANARY = "zzcanaryqx"
CONFIG_DIR = Path.home() / ".config" / "goumar"
REPO_ROOT = Path(__file__).resolve().parents[2]
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ConfigError(Exception):
    pass


class Lists(NamedTuple):
    phrases: List[str]
    phones: List[str]       # digit strings
    hashes: Set[str]
    salt: bytes
    version: str


def _env(name: str) -> Optional[str]:
    v = os.environ.get(name)
    return v if v and v.strip() else None


def _read_file(path: Path, what: str) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        raise ConfigError("%s file missing or unreadable" % what)
    if not text.strip():
        raise ConfigError("%s file is empty" % what)
    return text


def _from_env_or_file(content_env: str, file_env: str, default: str, what: str) -> str:
    content = _env(content_env)
    if content is not None:
        return content
    return _read_file(Path(os.environ.get(file_env) or (CONFIG_DIR / default)), what)


def _load_hash_text() -> str:
    parts = []
    n = 1
    while True:
        part = _env("GOUMAR_NAMES_HASHES_%d" % n)
        if part is None:
            break
        parts.append(part.strip())
        n += 1
    if parts:
        return "\n".join(parts)
    return _from_env_or_file("GOUMAR_NAMES_HASHES", "GOUMAR_NAMES_HASHES_FILE", "names.hashes", "hash list")


def parse_hashes(text: str) -> Set[str]:
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if not _HEX64.match(line):
            raise ConfigError("hash list contains a malformed line")
        out.add(line)
    if not out:
        raise ConfigError("hash list is empty")
    return out


def parse_denylist(text: str):
    phrases, phones = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("phone:"):
            digits = re.sub(r"\D", "", line[6:])
            if len(digits) < 7:
                raise ConfigError("denylist phone line has fewer than 7 digits")
            phones.append(digits)
        else:
            phrases.append(line)
    if not phrases and not phones:
        raise ConfigError("denylist has no entries")
    return phrases, phones


def compute_version(denylist_text: str, hashes: Set[str]) -> str:
    deny = "\n".join(
        l.strip() for l in denylist_text.splitlines() if l.strip() and not l.strip().startswith("#")
    )
    h = hashlib.sha256()
    h.update(deny.encode("utf-8"))
    h.update(b"\n--\n")
    h.update("\n".join(sorted(hashes)).encode("ascii"))
    return h.hexdigest()[:12]


def load_lists() -> Lists:
    deny_text = _from_env_or_file("GOUMAR_DENYLIST", "GOUMAR_DENYLIST_FILE", "denylist.txt", "denylist")
    phrases, phones = parse_denylist(deny_text)
    hashes = parse_hashes(_load_hash_text())
    salt = _from_env_or_file("GOUMAR_SALT", "GOUMAR_SALT_FILE", "salt", "salt").strip().encode("utf-8")
    if not salt:
        raise ConfigError("salt is empty")
    return Lists(phrases, phones, hashes, salt, compute_version(deny_text, hashes))


def check_version(lists: Lists) -> None:
    path = Path(os.environ.get("GOUMAR_VERSION_FILE") or (REPO_ROOT / "denylist.version"))
    try:
        expected = path.read_text(encoding="utf-8").split()[0]
    except (OSError, IndexError):
        raise ConfigError("denylist.version missing or empty")
    if expected != lists.version:
        raise ConfigError("version mismatch: expected %s, computed %s" % (expected, lists.version))


def hash_key(salt: bytes, key: str) -> str:
    return hashlib.sha256(salt + key.encode("utf-8")).hexdigest()


def canary_hash(salt: bytes) -> str:
    return hash_key(salt, normalize.normalize(CANARY))
