# Privacy tooling (stage 0)

Keeps real names, client details, server details and the owner's contact data out of
this public repository. Python 3.9+, stdlib only for hook/scrub; `hashlist.py` and the unit tests need
`wordfreq` (`pip install -r tools/privacy/requirements.txt`, ideally in `tools/.venv`).

## Secret inputs (never in git)

| Input | File (default) | Env override (path) | Env content (CI secret) |
|---|---|---|---|
| Denylist (phrases, `phone:` lines, `#` comments) | `~/.config/goumar/denylist.txt` | `GOUMAR_DENYLIST_FILE` | `GOUMAR_DENYLIST` |
| Salted name hashes (one sha256 hex per line) | `~/.config/goumar/names.hashes` | `GOUMAR_NAMES_HASHES_FILE` | `GOUMAR_NAMES_HASHES_1..N` (concatenated; use several when over 48 KB) |
| Salt | `~/.config/goumar/salt` | `GOUMAR_SALT_FILE` | `GOUMAR_SALT` |
| Expected version | `denylist.version` in the repo root (committed) | `GOUMAR_VERSION_FILE` | |

Content variables win over files. Anything missing, empty, malformed, or a version
mismatch stops every tool with exit code 2 (fail-closed, CI included). The version is
a short sha256 of the denylist and the hash list: `python3 tools/privacy/hook.py --print-version`;
put the result into `denylist.version` after every list change (the committed value is
a placeholder that matches nothing).

## Tools

- `normalize.py` - the one shared normaliser: NFKC, lowercase, Cyrillic to Latin (one table),
  accents removed, transliteration variants folded (`shch/sch>sh zh>j kh>h ts/tz>c ya/ia>a yu/iu>u y>i`, repeated letters collapsed), Russian/Spanish endings stripped (suffix list in the file), split on any
  non-alphanumeric character, n-grams of 1-3 tokens.
- `hashlist.py build --salt-file S --out OUT [--proof P] [--merge-into OLD] < names.txt` -
  hashes every n-gram with `sha256(salt + normalised)`. Single words that are in the en/ru/es
  dictionary (wordfreq zipf >= 3.5) or shorter than 3 letters are dropped; a dropped word that
  matches an entry of the proof set (raw names or 64-hex hashes) stops the build (exit 3).
  The list only grows (`--merge-into`). Output is counts only. A canary entry is always added.
- `scrub.py [FILE]` - replaces names, `t.me/*` channels, foreign URL hosts and denylisted phrases
  with `[name A]`, `[handle A]` (every handle that starts with `@`, except @airgum, @commintator, @commintator_bot, @commintator.app), `[email A]` (any address but me@goumar.eu), `[ip A]`, `[host A]` (host:port), `[path A]` (filesystem-root paths), `[phone A]`, `[channel A]`, `[site A]`, `[removed]`. Own addresses stay (goumar.eu,
  commintator.goumar.eu, github.com/airgum, t.me/airgum, instagram.com/commintator.app).
  Canary check first.
- `hook.py PATH... | --staged | --pushed | --print-version` - scans .md/.json/.txt, HTML
  (visible text, alt/title/meta only) and PDF (needs `pdftotext`). Prints
  `file<TAB>byte offset<TAB>rule id`, never the matched text; a banned word inside a file name
  is shown as `<redacted-path:...>`. Rule ids: `deny-phrase`, `hash-name`, `ipv4`, `ipv6`,
  `email`, `at-handle` (npm `@scope/pkg` is not a handle), `user-at-host`, `abs-path`, `host-port`, `secret-key`, `phone`. Exit 1 on findings.

## Git hooks

    git config core.hooksPath .githooks

`pre-commit` scans the staged blobs; `pre-push` scans every commit being pushed (file contents
and commit messages, `Co-Authored-By` trailers excluded). CI (`.github/workflows/privacy.yml`)
runs the unit tests and scans the whole repository with the secrets as environment.

## Tests

    python3 -m unittest discover -s tools/privacy/tests

Tests use invented words only. Real lists never enter git.
