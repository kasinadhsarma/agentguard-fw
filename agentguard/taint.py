"""Taint tracking: where did a tool argument come from?

Every piece of content in a session is labeled trusted (the user or the
system) or untrusted (web pages, files, emails, tool output). Before a
tool runs, the tracker checks whether the dangerous parts of the call
(recipient, URL, path, command) were authorized by trusted content, or
whether they only appear in untrusted content. It also detects when the
payload of a call copies text from sensitive data the agent has read.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import ContentItem, Trust
from .normalize import entity_in_text, plain_readings


# length of the sliding window used to detect copied text
SPAN_WINDOW = 24

EMAIL_PATTERN = re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+')
URL_PATTERN = re.compile(r'https?://[^\s\'"<>)]+', re.IGNORECASE)


def entity_for(value: str) -> str:
    """Reduce a target value to the part that identifies who or what.

    A URL is reduced to its host so that a different path on an
    authorized host still counts as authorized. Everything else is kept
    whole, lowercased and stripped.
    """
    cleaned = value.strip()
    if cleaned.lower().startswith(('http://', 'https://')):
        host = urlparse(cleaned).hostname
        if host:
            return host.lower()
    return cleaned.lower()


def contains_entity(entity: str, text: str) -> bool:
    """Return True when the entity appears in the text.

    Matching is done on every normalized reading of the text, so an
    entity written as "a [at] b [dot] c", percent-encoded, HTML-escaped,
    spread over spaces or hidden in a base64 blob is still found.
    """
    return entity_in_text(entity, text)


def extract_entities(text: str) -> list[str]:
    """Find the e-mail addresses and URL hosts mentioned in a text."""
    found: list[str] = []
    for reading in plain_readings(text):
        for match in EMAIL_PATTERN.findall(reading):
            found.append(match)
        for match in URL_PATTERN.findall(reading):
            found.append(entity_for(match))
    unique: list[str] = []
    for entity in found:
        if entity not in unique:
            unique.append(entity)
    return unique


def _flat_readings(text: str) -> list[str]:
    """Whitespace-collapsed readings of a text, for span comparison."""
    return [' '.join(reading.split()) for reading in plain_readings(text)]


def shared_span(payload: str, source: str) -> str | None:
    """Return a copied span when payload reuses text from the source.

    Slides a window over every reading of the payload and looks each
    window up in every reading of the source. Whitespace is collapsed
    and encodings are undone, so reformatting or base64-wrapping the
    copied text does not hide it.
    """
    source_readings = [
        reading for reading in _flat_readings(source)
        if len(reading) >= SPAN_WINDOW
    ]
    if not source_readings:
        return None

    step = max(1, SPAN_WINDOW // 4)
    for flat_payload in _flat_readings(payload):
        if len(flat_payload) < SPAN_WINDOW:
            continue
        for start in range(0, len(flat_payload) - SPAN_WINDOW + 1, step):
            window = flat_payload[start : start + SPAN_WINDOW]
            if any(window in reading for reading in source_readings):
                return window
    return None


def string_values(arguments: dict) -> list[str]:
    """Collect every string found in a tool call's arguments."""
    collected: list[str] = []
    for value in arguments.values():
        if isinstance(value, str):
            collected.append(value)
        elif isinstance(value, (list, tuple)):
            collected.extend(str(entry) for entry in value)
        elif isinstance(value, dict):
            collected.extend(string_values(value))
    return collected


class TaintTracker:
    """Keeps the labeled content of one session and answers origin queries."""

    def __init__(self) -> None:
        """Start with no content."""
        self.items: list[ContentItem] = []

    def add(self, item: ContentItem) -> None:
        """Record a new piece of content."""
        self.items.append(item)

    def trusted_text(self) -> str:
        """Join everything the user or system said."""
        return '\n'.join(
            item.text for item in self.items if item.trust == Trust.TRUSTED
        )

    def untrusted_items(self) -> list[ContentItem]:
        """Return all untrusted content seen so far."""
        return [
            item for item in self.items if item.trust == Trust.UNTRUSTED
        ]

    def sensitive_items(self) -> list[ContentItem]:
        """Return content flagged as sensitive (secrets the agent read)."""
        return [item for item in self.items if item.sensitive]

    def max_injection_score(self) -> float:
        """Return the highest injection score of any item in context."""
        scores = [item.injection_score for item in self.items]
        return max(scores) if scores else 0.0

    def is_user_authorized(self, value: str) -> bool:
        """Return True when trusted content names this target."""
        entity = entity_for(value)
        return contains_entity(entity, self.trusted_text())

    def untrusted_origin(self, value: str) -> ContentItem | None:
        """Return the untrusted item that names this target, if any."""
        entity = entity_for(value)
        for item in self.untrusted_items():
            if contains_entity(entity, item.text):
                return item
        return None

    def origins_of(self, text: str) -> list[ContentItem]:
        """Return the untrusted items a piece of model output draws on.

        An item counts as an origin when the text copies a span from it,
        or names an address or host that only untrusted content named.
        This is how a summary or rewrite of a poisoned page stays tainted.
        """
        origins: list[ContentItem] = []
        entities = [
            entity for entity in extract_entities(text)
            if not self.is_user_authorized(entity)
        ]
        for item in self.untrusted_items():
            copied = shared_span(text, item.text) is not None
            named = any(
                contains_entity(entity, item.text) for entity in entities
            )
            if copied or named:
                origins.append(item)
        return origins

    def exfiltrated_span(
        self,
        arguments: dict,
    ) -> tuple[ContentItem, str] | None:
        """Detect payload text copied from sensitive content."""
        for sensitive in self.sensitive_items():
            for value in string_values(arguments):
                span = shared_span(value, sensitive.text)
                if span is not None:
                    return sensitive, span
        return None
