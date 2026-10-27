"""Heuristic prompt injection detector.

This is the fast, offline first line of defense. It scans a piece of
untrusted content for phrases and structures that attackers use to
hijack an agent, and returns a score between 0 and 1 plus the findings.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .models import Finding


# characters that render as nothing but can smuggle hidden instructions
ZERO_WIDTH_CHARS = '​‌‍⁠﻿'

# a score at or above this value is treated as a likely injection
SUSPICIOUS_THRESHOLD = 0.5


@dataclass(frozen=True)
class Pattern:
    """One detection rule: a regex, a weight and a human description."""

    rule_id: str
    regex: re.Pattern[str]
    weight: float
    description: str


def _compile(expression: str) -> re.Pattern[str]:
    """Compile a case-insensitive, multiline, dot-matches-newline regex."""
    return re.compile(expression, re.IGNORECASE | re.MULTILINE | re.DOTALL)


PATTERNS: list[Pattern] = [
    Pattern(
        rule_id='override_instructions',
        regex=_compile(
            r'ignore\s+(all\s+|any\s+)?(the\s+)?'
            r'(previous|prior|above|earlier|preceding)\s+'
            r'(instructions?|prompts?|rules?|directions?)'
        ),
        weight=0.7,
        description='tries to override earlier instructions',
    ),
    Pattern(
        rule_id='disregard_user',
        regex=_compile(
            r'(disregard|forget|override)\s+(everything|all|your|the)'
            r'\s+(above|previous|prior|instructions?|rules?|guidelines?)'
        ),
        weight=0.6,
        description='tells the agent to disregard its guidelines',
    ),
    Pattern(
        rule_id='role_hijack',
        regex=_compile(
            r'(you\s+are\s+now\b|new\s+instructions?\s*:|'
            r'from\s+now\s+on\s+(you|act)\b)'
        ),
        weight=0.5,
        description='attempts to reassign the agent role',
    ),
    Pattern(
        rule_id='system_marker',
        regex=_compile(
            r'(^\s*(system|assistant)\s*:|<\|im_start\|>|\[/?INST\]|'
            r'<\s*system\s*>)'
        ),
        weight=0.5,
        description='fakes a system or assistant message marker',
    ),
    Pattern(
        rule_id='secrecy',
        regex=_compile(
            r'(do\s+not|don\'t|never)\s+(tell|inform|mention|alert|notify)'
            r'.{0,30}\buser\b|without\s+(telling|informing|notifying)'
            r'\s+the\s+user'
        ),
        weight=0.6,
        description='asks the agent to hide actions from the user',
    ),
    Pattern(
        rule_id='exfiltration',
        regex=_compile(
            r'\b(send|forward|email|mail|post|upload|transmit|leak)\b'
            r'.{0,120}\b(to|at)\b.{0,80}(@[\w.-]+|https?://\S+)'
        ),
        weight=0.55,
        description='instructs sending data to an external address',
    ),
    Pattern(
        rule_id='sensitive_target',
        regex=_compile(
            r'(\.ssh|id_rsa|\.env\b|api[_ -]?keys?|passwords?|'
            r'credentials?|secrets?|private\s+key|access\s+token)'
        ),
        weight=0.3,
        description='mentions secrets, keys or credentials',
    ),
    Pattern(
        rule_id='hidden_markup',
        regex=_compile(
            r'(<!--.{0,300}?(ignore|instruction|assistant|send|email).{0,300}?-->|'
            r'display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden)'
        ),
        weight=0.35,
        description='hides text from humans using markup or styling',
    ),
    Pattern(
        rule_id='base64_blob',
        regex=_compile(r'[A-Za-z0-9+/]{120,}={0,2}'),
        weight=0.2,
        description='contains a long encoded blob that may hide a payload',
    ),
    Pattern(
        rule_id='addresses_ai',
        regex=_compile(
            r'(important|urgent|attention|note)\s*(to|for)?\s*'
            r'(the\s+)?(ai|assistant|agent|llm|model)\b'
        ),
        weight=0.4,
        description='speaks directly to the AI instead of the human reader',
    ),
]


def normalize(text: str) -> str:
    """Normalize unicode and strip zero-width characters before matching."""
    folded = unicodedata.normalize('NFKC', text)
    for character in ZERO_WIDTH_CHARS:
        folded = folded.replace(character, '')
    return folded


def _excerpt(text: str, start: int, end: int, radius: int = 40) -> str:
    """Return a short single-line excerpt around a match."""
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return ' '.join(text[left:right].split())


def has_zero_width(text: str) -> bool:
    """Return True when the text hides characters that render as nothing."""
    return any(character in text for character in ZERO_WIDTH_CHARS)


def scan(text: str) -> tuple[float, list[Finding]]:
    """Scan text and return an injection score in [0, 1] and the findings.

    Each distinct rule contributes once. Weights combine as independent
    evidence: score = 1 - product(1 - weight).
    """
    findings: list[Finding] = []
    cleaned = normalize(text)

    for pattern in PATTERNS:
        match = pattern.regex.search(cleaned)
        if match is None:
            continue
        findings.append(
            Finding(
                rule_id=pattern.rule_id,
                description=pattern.description,
                weight=pattern.weight,
                excerpt=_excerpt(cleaned, match.start(), match.end()),
            )
        )

    if has_zero_width(text):
        findings.append(
            Finding(
                rule_id='zero_width',
                description='contains invisible zero-width characters',
                weight=0.3,
                excerpt='(invisible characters)',
            )
        )

    remaining = 1.0
    for finding in findings:
        remaining *= 1.0 - finding.weight

    return round(1.0 - remaining, 4), findings


def is_suspicious(score: float) -> bool:
    """Return True when a score crosses the suspicious threshold."""
    return score >= SUSPICIOUS_THRESHOLD
