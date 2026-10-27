"""Privacy hook: scan files for banned content. Prints file, byte offset and rule id
only (tab separated); never the matched text.

  hook.py PATH...        scan files / directories
  hook.py --staged       scan the staged blobs (pre-commit)
  hook.py --pushed       read pre-push ref lines on stdin; scan every commit being pushed
  hook.py --print-version  print the computed version of denylist + hash list

Exit codes: 0 clean, 1 findings, 2 configuration error (fail-closed: missing or
empty denylist / hash list / salt, malformed list, missing or mismatching
denylist.version, canary not detected, pdftotext missing while a PDF is scanned).
"""
from __future__ import annotations

import bisect
import hashlib
import os
import shutil
import subprocess
import sys
from html.parser import HTMLParser
from typing import Callable, List, Optional, Tuple

import config
import detect

PLAIN_EXT = {".md", ".markdown", ".txt", ".json"}
HTML_EXT = {".html", ".htm"}
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__"}
_SKIP_TAGS = {"script", "style", "svg"}
Extracted = Tuple[str, Callable[[int], int]]  # text, char offset -> byte offset


class _VisibleText(HTMLParser):
    """Collects visible text, alt/title attributes and meta content."""

    def __init__(self, src: str):
        super().__init__(convert_charrefs=True)
        self.src = src
        self.starts = [0]
        for line in src.split("\n"):
            self.starts.append(self.starts[-1] + len(line) + 1)
        self.segments: List[Tuple[int, int]] = []  # (doc_start, src_char)
        self.doc = ""
        self.skip = 0

    def _src_char(self) -> int:
        line, col = self.getpos()
        return self.starts[line - 1] + col

    def _add(self, text: str, src_char: int) -> None:
        self.segments.append((len(self.doc), src_char))
        self.doc += text + "\n"

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self.skip += 1
            return
        pos = self._src_char()
        for name, value in attrs:
            if value and (name in ("alt", "title") or (tag == "meta" and name == "content")):
                self._add(value, pos)

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip and data.strip():
            self._add(data, self._src_char())


def _plain(src: str) -> Extracted:
    return src, lambda i: len(src[:i].encode("utf-8"))


def _html(src: str) -> Extracted:
    p = _VisibleText(src)
    p.feed(src)
    p.close()
    starts = [s for s, _ in p.segments]

    def to_byte(i: int) -> int:
        k = max(bisect.bisect_right(starts, i) - 1, 0)
        if not p.segments:
            return 0
        doc_start, src_char = p.segments[k]
        return len(src[: src_char + (i - doc_start)].encode("utf-8"))

    return p.doc, to_byte


def _pdf(data: bytes) -> Extracted:
    exe = shutil.which("pdftotext")
    if not exe:
        raise config.ConfigError("pdftotext not installed; cannot scan a PDF (fail-closed)")
    r = subprocess.run([exe, "-enc", "UTF-8", "-", "-"], input=data, capture_output=True)
    if r.returncode != 0:
        raise config.ConfigError("pdftotext failed on a PDF (fail-closed)")
    return _plain(r.stdout.decode("utf-8", "replace"))


def extract(name: str, data: bytes) -> Optional[Extracted]:
    ext = os.path.splitext(name)[1].lower()
    if ext in PLAIN_EXT:
        return _plain(data.decode("utf-8", "replace"))
    if ext in HTML_EXT:
        return _html(data.decode("utf-8", "replace"))
    if ext == ".pdf":
        return _pdf(data)
    return None


class Scanner:
    def __init__(self, lists: config.Lists):
        self.lists = lists
        self.index = detect.PhraseIndex(lists.phrases)
        self.files = 0
        self.findings = 0

    def _emit(self, display: str, offset: int, rule: str) -> None:
        self.findings += 1
        print("%s\t%d\t%s" % (display, offset, rule))

    def scan_bytes(self, label: str, name: str, data: bytes) -> None:
        # The path itself can carry a banned word: scan it and redact it if so.
        display = label
        for _, _, rule in detect.scan(label, self.lists, self.index, names_only=True):
            display = "<redacted-path:%s>" % hashlib.sha256(label.encode()).hexdigest()[:8]
            self._emit(display, 0, rule)
        ex = extract(name, data)
        if ex is None:
            return
        self.files += 1
        text, to_byte = ex
        for start, _, rule in detect.scan(text, self.lists, self.index):
            self._emit(display, to_byte(start), rule)

    def scan_text(self, label: str, text: str) -> None:
        self.files += 1
        for start, _, rule in detect.scan(text, self.lists, self.index):
            self._emit(label, len(text[:start].encode("utf-8")), rule)

    def scan_path(self, path: str) -> None:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for f in sorted(files):
                    self.scan_path(os.path.join(root, f))
            return
        with open(path, "rb") as fh:
            self.scan_bytes(path, path, fh.read())


def _git(*args: str) -> bytes:
    r = subprocess.run(["git", "-c", "core.quotepath=off"] + list(args), capture_output=True)
    if r.returncode != 0:
        raise config.ConfigError("git command failed: %s" % args[0])
    return r.stdout


def scan_staged(sc: Scanner) -> None:
    out = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    for raw in filter(None, out.split(b"\0")):
        path = raw.decode("utf-8", "replace")
        sc.scan_bytes(path, path, _git("show", ":" + path))


def _strip_trailers(msg: str) -> str:
    return "\n".join(l for l in msg.splitlines() if not l.lower().startswith("co-authored-by:"))


def scan_pushed(sc: Scanner, stdin_text: str) -> None:
    zero = "0" * 40
    seen_blobs = set()
    for line in stdin_text.splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[1] == zero:
            continue
        lsha, rsha = parts[1], parts[3]
        rng = [lsha, "--not", "--remotes"] if rsha == zero else ["%s..%s" % (rsha, lsha)]
        for commit in _git("rev-list", *rng).decode().split():
            short = commit[:8]
            sc.scan_text("commit-message@" + short,
                         _strip_trailers(_git("log", "-1", "--format=%B", commit).decode("utf-8", "replace")))
            tree = _git("diff-tree", "-r", "--root", "--no-commit-id", "--no-renames",
                        "--diff-filter=ACMR", "-z", commit).split(b"\0")
            for meta, raw in zip(tree[0::2], tree[1::2]):
                blob = meta.split()[3].decode()
                path = raw.decode("utf-8", "replace")
                if blob in seen_blobs:
                    continue
                seen_blobs.add(blob)
                sc.scan_bytes("%s@%s" % (path, short), path, _git("cat-file", "blob", blob))


def main(argv: List[str]) -> int:
    try:
        lists = config.load_lists()
        if "--print-version" in argv:
            print(lists.version)
            return 0
        config.check_version(lists)
        detect.check_canary(lists)
        sc = Scanner(lists)
        if "--staged" in argv:
            scan_staged(sc)
        elif "--pushed" in argv:
            scan_pushed(sc, sys.stdin.read())
        else:
            paths = [a for a in argv if not a.startswith("--")]
            if not paths:
                raise config.ConfigError("no paths given")
            for p in paths:
                if not os.path.exists(p):
                    raise config.ConfigError("path does not exist")
                sc.scan_path(p)
    except config.ConfigError as e:
        print("privacy-hook: %s" % e, file=sys.stderr)
        return 2
    except Exception as e:  # never echo exception text: it could contain content
        print("privacy-hook: internal error (%s)" % type(e).__name__, file=sys.stderr)
        return 2
    print("privacy-hook: version=%s files=%d findings=%d" % (lists.version, sc.files, sc.findings),
          file=sys.stderr)
    return 1 if sc.findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
