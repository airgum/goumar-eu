"""Replace known names, channels, sites and denylisted phrases with stable placeholders.

  scrub.py [FILE] > cleaned.txt      (reads stdin when FILE is omitted)

Placeholders: [name A], [handle A], [email A], [ip A], [host A], [path A], [phone A], [channel A], [site A], [removed]; the same normalised
subject gets the same letter within one run. Runs the canary check first and
stops (exit 2) when it fails, when any secret input is missing, or when the
list version does not match denylist.version. The list version is printed to
stderr.
"""
from __future__ import annotations

import re
import sys
from typing import List, Tuple

import config
import detect
import normalize

ALLOWED_URLS = [  # (host, path prefix or "")
    ("goumar.eu", ""), ("commintator.goumar.eu", ""), ("github.com", "/airgum"),
    ("t.me", "/airgum"), ("instagram.com", "/commintator.app"),
]
_TLDS = ("com|org|net|io|eu|ru|es|app|dev|me|ai|co|info|xyz|cy|ua|by|tv|uk|de|fr|it|su|club|online|site|pro")
_URL = re.compile(
    r"(?i)(?:\b(?:https?://|www\.)[^\s<>\"')\]]+)"
    r"|(?:(?<![\w@./-])(?:[a-z0-9-]+\.)+(?:%s)\b(?:/[^\s<>\"')\]]*)?)" % _TLDS
)
_CHANNEL_HOSTS = ("t.me", "telegram.me")

Span = Tuple[int, int, str, str]  # start, end, kind, key


def _letters(n: int) -> str:
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _url_spans(text: str) -> List[Span]:
    spans: List[Span] = []
    for m in _URL.finditer(text):
        raw = m.group().rstrip(".,;:!?")
        rest = re.sub(r"(?i)^(?:https?://)?(?:www\.)?", "", raw)
        m2 = re.match(r"([^/?#:]+)(?::\d+)?([/?#].*)?$", rest)
        if not m2:
            continue
        host, path = m2.group(1).lower(), (m2.group(2) or "")
        if host in _CHANNEL_HOSTS:
            segs = [s for s in path.lstrip("/").split("/") if s]
            if segs and segs[0].lower() == "s":
                segs = segs[1:]
            handle = segs[0].lower().lstrip("+") if segs else ""
            if handle == "airgum":
                continue
            spans.append((m.start(), m.start() + len(raw), "channel", handle or host))
            continue
        allowed = any(host == h and (not p or path.lower() == p or path.lower().startswith(p + "/"))
                      for h, p in ALLOWED_URLS)
        if not allowed:
            spans.append((m.start(), m.start() + len(raw), "site", host))
    return spans


def scrub_text(text: str, lists: config.Lists) -> str:
    masked = detect.mask_whitelist(text)
    tokens = normalize.tokenize(masked)
    spans: List[Span] = _url_spans(text)
    spans += [(s, e, "handle", k) for s, e, k in detect.at_handles(masked)]
    spans += [(s, e, "email", k) for s, e, k in detect.emails(masked)]
    for s, e, _, k in detect.phone_spans(masked, lists.phones):
        spans.append((s, e, "phone", k))
    for s, e, rule, k in detect.ip_spans(masked):
        spans.append((s, e, "ip", k))
    for s, e, _, k in detect.host_port_spans(masked):
        spans.append((s, e, "host", k))
    for s, e, _, k in detect.path_spans(masked):
        spans.append((s, e, "path", k))
    for s, e, _ in detect.phrase_hits(tokens, detect.PhraseIndex(lists.phrases)):
        spans.append((s, e, "removed", ""))
    for key, i, j in normalize.ngrams(tokens):
        if i == j and len(key) < normalize.MIN_STEM:
            continue
        if config.hash_key(lists.salt, key) in lists.hashes:
            spans.append((tokens[i].start, tokens[j].end, "name", key))
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    chosen: List[Span] = []
    last_end = -1
    for sp in spans:
        if sp[0] >= last_end:
            chosen.append(sp)
            last_end = sp[1]
    letters = {"name": {}, "channel": {}, "site": {}, "handle": {}, "email": {}, "ip": {}, "host": {}, "path": {}, "phone": {}}
    out, pos = [], 0
    for s, e, kind, key in chosen:
        out.append(text[pos:s])
        if kind == "removed":
            out.append("[removed]")
        else:
            table = letters[kind]
            if key not in table:
                table[key] = _letters(len(table))
            out.append("[%s %s]" % (kind, table[key]))
        pos = e
    out.append(text[pos:])
    return "".join(out)


def check_canary(lists: config.Lists) -> None:
    probe = "probe %s probe" % config.CANARY
    cleaned = scrub_text(probe, lists)
    if config.CANARY in cleaned or "[name" not in cleaned:
        raise config.ConfigError("canary not replaced: hash list is not working")


def main(argv: List[str]) -> int:
    try:
        lists = config.load_lists()
        config.check_version(lists)
        check_canary(lists)
        if argv:
            with open(argv[0], encoding="utf-8") as fh:
                text = fh.read()
        else:
            text = sys.stdin.read()
    except config.ConfigError as e:
        print("scrub: %s" % e, file=sys.stderr)
        return 2
    except OSError:
        print("scrub: input file unreadable", file=sys.stderr)
        return 2
    print("scrub: lists version %s" % lists.version, file=sys.stderr)
    sys.stdout.write(scrub_text(text, lists))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
