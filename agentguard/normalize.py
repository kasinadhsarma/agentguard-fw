"""Text normalization for matching targets and copied data.

Attackers hide a target (an address, a host, a path) so that a plain
substring search misses it. This module turns one piece of text into a
small set of equivalent readings, and the taint tracker matches against
all of them.

Readings produced by variants():

  plain       NFKC folded, lowercased, zero-width characters removed
  html        HTML entities decoded            (&#64; -> @)
  percent     URL escapes decoded              (%40 -> @)
  spelled     spelled-out symbols replaced     ([at] -> @, dot -> .)
  compact     all whitespace removed           (a @ b . c -> a@b.c)
  base64      long base64 blobs decoded, then normalized again

The "compact" reading is deliberately flagged so callers apply it only
to long entities, where an accidental match across word boundaries is
very unlikely.
"""

from __future__ import annotations

import base64
import binascii
import functools
import html
import re
import unicodedata
from urllib.parse import unquote


ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD],
)

# bracketed or spaced-out spellings of "@" and "."
BRACKETED_AT = re.compile(r'\s*[\[\(\{<]\s*at\s*[\]\)\}>]\s*')
BRACKETED_DOT = re.compile(r'\s*[\[\(\{<]\s*dot\s*[\]\)\}>]\s*')
WORD_AT_WORD = re.compile(r'(?<=\w)\s+at\s+(?=[\w-]+\s*(?:\.|\bdot\b))')
WORD_DOT_WORD = re.compile(r'(?<=\w)\s+dot\s+(?=\w)')

BASE64_BLOB = re.compile(r'[A-Za-z0-9+/_-]{16,}={0,2}')

# prefix marking a compact reading inside the variants() result
COMPACT_TAG = '\x00'

# entities shorter than this are never matched on the compact reading
COMPACT_MIN_LENGTH = 8

# how many decoding passes to apply (guards against nested encodings)
MAX_DECODE_PASSES = 2
MAX_BLOB_DECODES = 20


def fold(text: str) -> str:
    """Case-fold, apply NFKC and drop zero-width characters."""
    normalized = unicodedata.normalize('NFKC', text)
    return normalized.translate(ZERO_WIDTH).lower()


def unspell(text: str) -> str:
    """Replace spelled-out "at" and "dot" with the symbols they stand for."""
    text = BRACKETED_AT.sub('@', text)
    text = BRACKETED_DOT.sub('.', text)
    text = WORD_AT_WORD.sub('@', text)
    return WORD_DOT_WORD.sub('.', text)


def compact(text: str) -> str:
    """Remove all whitespace."""
    return ''.join(text.split())


def decode_blobs(text: str) -> list[str]:
    """Decode base64 blobs found in the text, keeping printable results."""
    decoded: list[str] = []
    for match in BASE64_BLOB.findall(text)[:MAX_BLOB_DECODES]:
        padded = match + '=' * (-len(match) % 4)
        try:
            raw = base64.b64decode(
                padded.replace('-', '+').replace('_', '/'),
                validate=True,
            )
            candidate = raw.decode('utf-8')
        except (binascii.Error, ValueError):
            continue
        if candidate and (candidate.isprintable() or '\n' in candidate):
            decoded.append(candidate)
    return decoded


@functools.lru_cache(maxsize=512)
def variants(text: str) -> tuple[str, ...]:
    """Return the readings of the text (see the module docstring).

    The first element is always the plain reading. The compact reading,
    when it differs, is the last element of its group and can be told
    apart with is_compact_reading().
    """
    readings: list[str] = []
    seen: set[str] = set()

    def add(reading: str) -> None:
        if reading and reading not in seen:
            seen.add(reading)
            readings.append(reading)

    def expand(source: str, depth: int) -> None:
        plain = fold(source)
        add(plain)

        step = plain
        for _ in range(MAX_DECODE_PASSES):
            step = unquote(html.unescape(step))
            add(step)

        add(unspell(step))

        if depth == 0:
            for blob in decode_blobs(source):
                expand(blob, depth + 1)

    expand(text, 0)

    for reading in list(readings):
        flat = compact(reading)
        if flat != reading:
            add(COMPACT_TAG + flat)
    return tuple(readings)


def is_compact_reading(reading: str) -> bool:
    """Return True for readings produced by whitespace removal."""
    return reading.startswith(COMPACT_TAG)


def entity_in_text(entity: str, text: str) -> bool:
    """Return True when the entity appears under any reading of the text."""
    wanted = fold(entity)
    if not wanted:
        return False

    flat_wanted = compact(wanted)
    for reading in variants(text):
        if is_compact_reading(reading):
            if len(flat_wanted) >= COMPACT_MIN_LENGTH:
                if flat_wanted in reading[len(COMPACT_TAG):]:
                    return True
        elif wanted in reading:
            return True
    return False


def plain_readings(text: str) -> list[str]:
    """Return the readings that keep word boundaries (no compact ones)."""
    return [r for r in variants(text) if not is_compact_reading(r)]
