"""Shared normaliser for every privacy tool (hash list, scrub, hook).

Pipeline per token:
  1. split the text into alphanumeric runs (everything else, including
     whitespace, "_ / . - @ :" and all punctuation, is a separator; a leading
     "@" therefore disappears);
  2. NFKC + lowercase;
  3. Cyrillic -> Latin with ONE fixed table (TRANSLIT), then accents removed
     (NFKD, combining marks dropped, so "n with tilde" becomes "n");
  4. transliteration variants folded (fold(), table FOLD below) so that
     "Zhebrov", "Jebrov" and "Жебров" are one name;
  5. inflectional endings stripped (SUFFIXES, longest first, repeated until
     nothing changes, never shortening the stem below MIN_STEM letters).

FOLD, applied in this order to the transliterated word:
  shch, sch -> sh | zh -> j | kh -> h | ts, tz -> c | ya, ia -> a |
  yu, iu -> u | y -> i | any repeated letter -> one letter ("ff" -> "f").
The suffix list is folded with the same function, so stripping stays consistent.

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
    "ж": "zh", "з": "z", "и": "i", "й": "i", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
    "і": "i", "ї": "yi", "є": "e", "ґ": "g",
}

# Inflectional endings, applied to the TRANSLITERATED form.
# Russian (case/number/gender endings of surnames and nouns, transliterated):
_RU = [
    "a", "y", "i", "u", "e", "o", "ya", "yu", "ov", "ev", "om", "em", "am",
    "ym", "im", "oi", "ei", "ai", "ii", "ami", "yami", "ymi", "imi", "ogo",
    "ego", "omu", "emu", "akh", "ykh", "ikh", "yakh", "yam", "oyu", "eyu",
    "aya", "yaya", "uyu", "oe", "ee", "yi",
]
# Spanish plurals/gender (the vowels are already in the list above):
_ES = ["s", "es", "os", "as"]


class Token(NamedTuple):
    start: int      # char offset of the token in the original text
    end: int
    lower: str      # NFKC + lowercase, original script (used for dictionary check)
    translit: str   # transliterated, no accents
    stem: str       # translit with endings stripped (the hashed form)


_FOLD = [("shch", "sh"), ("sch", "sh"), ("zh", "j"), ("kh", "h"), ("ts", "c"), ("tz", "c"),
         ("ya", "a"), ("ia", "a"), ("yu", "u"), ("iu", "u"), ("y", "i")]
_REPEAT = re.compile(r"(.)\1+")


def fold(word: str) -> str:
    for a, b in _FOLD:
        word = word.replace(a, b)
    return _REPEAT.sub(r"\1", word)


SUFFIXES = sorted({fold(x) for x in _RU + _ES}, key=lambda x: (-len(x), x))


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
        tr = fold(transliterate(lower))
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
