"""Detection rules shared by hook.py and scrub.py. Returns offsets and rule ids
only; the matched text never leaves this module's callers."""
from __future__ import annotations

import ipaddress
import re
from typing import List, Tuple

import config
import normalize

# Exact phrases that are never reported (applied first, case-insensitive).
WHITELIST = [
    "Granada, Spain", "Гранада, Испания", "Granada, España", "Sierra Nevada",
    "Сьерра-Невада", "@commintator.app", "airgum", "me@goumar.eu",
]

MAX_WINDOW = 6  # tokens a static phrase may span (JobSpy vs "Job Spy")

Hit = Tuple[int, int, str]  # (start, end, rule_id)

def _wl_alt(p: str) -> str:
    lead = r"(?<![\w-])" if p[0].isalnum() else ""
    return lead + re.escape(p) + r"(?!\.?[\w-])"  # whole phrase only: not "airgum.evil", not "...app.evil.com"


_WL_RE = re.compile("|".join(_wl_alt(p) for p in sorted(WHITELIST, key=len, reverse=True)), re.I)


def mask_whitelist(text: str) -> str:
    """Blank out whitelisted phrases, keeping every offset intact."""
    return _WL_RE.sub(lambda m: " " * len(m.group()), text)


class PhraseIndex:
    def __init__(self, phrases: List[str]):
        self.by_translit = set()
        self.by_stem = set()
        for p in phrases:
            toks = normalize.tokenize(p)
            if not toks:
                continue
            self.by_translit.add("".join(t.translit for t in toks))
            self.by_stem.add("".join(t.stem for t in toks))
        self.maxlen = max([len(k) for k in self.by_translit | self.by_stem] or [0])


def phrase_hits(tokens: List[normalize.Token], index: PhraseIndex) -> List[Hit]:
    hits: List[Hit] = []
    for i in range(len(tokens)):
        tk = sk = ""
        for j in range(i, min(i + MAX_WINDOW, len(tokens))):
            tk += tokens[j].translit
            sk += tokens[j].stem
            if len(tk) > index.maxlen and len(sk) > index.maxlen:
                break
            if tk in index.by_translit or sk in index.by_stem:
                hits.append((tokens[i].start, tokens[j].end, "deny-phrase"))
    return hits


def name_hits(tokens: List[normalize.Token], hashes, salt: bytes) -> List[Hit]:
    hits: List[Hit] = []
    for key, i, j in normalize.ngrams(tokens):
        if i == j and len(key) < normalize.MIN_STEM:
            continue
        if config.hash_key(salt, key) in hashes:
            hits.append((tokens[i].start, tokens[j].end, "hash-name"))
    return hits


_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
_IPV6 = re.compile(r"(?<![\w:])[0-9A-Fa-f:]{3,}(?![\w:])")
_AT = re.compile(r"(?<![\w.+-])[A-Za-z0-9._+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*")
_HANDLE = re.compile(r"(?<![\w.+\-])@([A-Za-z0-9_]{3,})(?![A-Za-z0-9_]|/)")  # "@scope/pkg" is not a handle
ALLOWED_HANDLES = {"airgum", "commintator", "commintator_bot"}  # "@commintator.app" is in WHITELIST
_PATH = re.compile(r"(?<![\w.\-/])/(?:Users|etc|opt|var|home)(?![A-Za-z0-9_])")
_HOSTPORT = re.compile(r"(?<![\w.\-])[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?:(\d{2,5})(?![\w])")
_KEY = re.compile(r"(?<![\w])(?:sk-[A-Za-z0-9_\-]{16,}|gh[pousr]_[A-Za-z0-9]{20,})")
_PHONE_RUN = re.compile(r"\+?\d(?:[\d\s().\-]*\d)?")


def at_handles(masked: str):
    """(start, end, lowercase handle) of every non-allowlisted @handle outside emails."""
    return [(m.start(), m.end(), m.group(1).lower()) for m in _HANDLE.finditer(masked)
            if m.group(1).lower() not in ALLOWED_HANDLES]


def emails(masked: str):
    """(start, end, lowercase address) of every address with a dotted domain."""
    return [(m.start(), m.end(), m.group().lower()) for m in _AT.finditer(masked)
            if "." in m.group().split("@", 1)[1]]


def _pattern_hits(text: str, phones: List[str]) -> List[Hit]:
    hits: List[Hit] = []
    for m in _IPV4.finditer(text):
        if all(int(p) <= 255 for p in m.group().split(".")):
            hits.append((m.start(), m.end(), "ipv4"))
    for m in _IPV6.finditer(text):
        s = m.group()
        if s.count(":") >= 2:
            try:
                ipaddress.IPv6Address(s)
            except ValueError:
                continue
            hits.append((m.start(), m.end(), "ipv6"))
    for m in _AT.finditer(text):
        domain = m.group().split("@", 1)[1]
        hits.append((m.start(), m.end(), "email" if "." in domain else "user-at-host"))
    for m in at_handles(text):
        hits.append((m[0], m[1], "at-handle"))
    for m in _PATH.finditer(text):
        hits.append((m.start(), m.end(), "abs-path"))
    for m in _HOSTPORT.finditer(text):
        host = m.group()[: m.group().rindex(":")]
        if any(c.isalpha() or c == "." for c in host) and int(m.group(1)) <= 65535:
            hits.append((m.start(), m.end(), "host-port"))
    for m in _KEY.finditer(text):
        hits.append((m.start(), m.end(), "secret-key"))
    if phones:
        variants = set()
        for d in phones:
            variants.add(d)
            if len(d) >= 10:
                variants.add(d[-9:])
        for m in _PHONE_RUN.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if any(v in digits for v in variants):
                hits.append((m.start(), m.end(), "phone"))
    return hits


def scan(text: str, lists: config.Lists, index: PhraseIndex = None, names_only: bool = False) -> List[Hit]:
    """All rule hits for `text`, whitelist applied first, sorted by offset.
    names_only: skip the pattern rules (used for file paths)."""
    masked = mask_whitelist(text)
    tokens = normalize.tokenize(masked)
    index = index or PhraseIndex(lists.phrases)
    hits = phrase_hits(tokens, index) + name_hits(tokens, lists.hashes, lists.salt)
    if not names_only:
        hits += _pattern_hits(masked, lists.phones)
    return sorted(set(hits))


def check_canary(lists: config.Lists) -> None:
    probe = "probe %s probe" % config.CANARY
    if not any(rule == "hash-name" for _, _, rule in scan(probe, lists)):
        raise config.ConfigError("canary not detected: hash list is not working")
