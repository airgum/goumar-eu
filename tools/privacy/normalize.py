"""Shared normaliser for every privacy tool (hash list, scrub, hook).

Pipeline per token:
  1. split the text into alphanumeric runs (everything else, including
     whitespace, "_ / . - @ :" and all punctuation, is a separator; a leading
     "@" therefore disappears);
  2. NFKC + lowercase;
  3. Cyrillic -> Latin with ONE fixed table (TRANSLIT), then accents removed
     (NFKD, combining marks dropped, so "n with tilde" becomes "n");
  4. inflectional endings stripped (SUFFIXES, longest first, repeated until
     nothing changes, never shortening the stem below MIN_STEM letters).

N-grams are 1..MAX_NGRAM consecutive stems joined with one space.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Iterator, List, NamedTuple, Tuple

MAX_NGRAM = 3
MIN_STEM = 3

_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)

# One fixed Cyrillic -> Latin table (lowercase input only).
TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "j", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
    "і": "i", "ї": "yi", "є": "e", "ґ": "g",
}

# Inflectional endings, applied to the TRANSLITERATED form.
# Russian (case/number/gender endings of surnames and nouns, transliterated):
_RU = [
    "a", "y", "i", "u", "e", "o", "ya", "yu", "ov", "ev", "om", "em", "am",
    "ym", "im", "oj", "ej", "aj", "ij", "ami", "yami", "ymi", "imi", "ogo",
    "ego", "omu", "emu", "akh", "ykh", "ikh", "yakh", "yam", "oyu", "eyu",
    "aya", "yaya", "uyu", "oe", "ee", "yj",
]
# Spanish plurals/gender (the vowels are already in the list above):
_ES = ["s", "es", "os", "as"]
SUFFIXES = sorted(set(_RU + _ES), key=lambda s: (-len(s), s))


class Token(NamedTuple):
    start: int      # char offset of the token in the original text
    end: int
    lower: str      # NFKC + lowercase, original script (used for dictionary check)
    translit: str   # transliterated, no accents
    stem: str       # translit with endings stripped (the hashed form)


def transliterate(s: str) -> str:
    out = "".join(TRANSLIT.get(ch, ch) for ch in s)
    out = unicodedata.normalize("NFKD", out)
    out = "".join(ch for ch in out if unicodedata.category(ch) != "Mn")
    return "".join(ch for ch in out if ch.isalnum())


def stem(word: str) -> str:
    changed = True
    while changed:
        changed = False
        for suf in SUFFIXES:
            if word.endswith(suf) and len(word) - len(suf) >= MIN_STEM:
                word = word[: -len(suf)]
                changed = True
                break
    return word


def tokenize(text: str) -> List[Token]:
    tokens: List[Token] = []
    for m in _TOKEN_RE.finditer(text):
        lower = unicodedata.normalize("NFKC", m.group()).lower()
        lower = "".join(ch for ch in lower if ch.isalnum())
        if not lower:
            continue
        tr = transliterate(lower)
        if not tr:
            continue
        tokens.append(Token(m.start(), m.end(), lower, tr, stem(tr)))
    return tokens


def ngrams(tokens: List[Token], max_n: int = MAX_NGRAM) -> Iterator[Tuple[str, int, int]]:
    """Yield (key, first_index, last_index) for every 1..max_n window."""
    for i in range(len(tokens)):
        for j in range(i, min(i + max_n, len(tokens))):
            yield " ".join(t.stem for t in tokens[i : j + 1]), i, j


def normalize(text: str) -> str:
    """Whole-string normal form (stems joined by one space)."""
    return " ".join(t.stem for t in tokenize(text))
