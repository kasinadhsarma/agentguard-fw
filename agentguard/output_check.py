"""Check the text a model shows to the user for data-leaking references.

Some attacks never call a tool. They get the model to write a markdown
image or link whose address carries a secret; the chat client then loads
the image on its own (EchoLeak) or the user clicks the link (Slack AI).
Tool-call rules cannot see that. This check looks at the final answer
instead.

For every address in the answer it asks:

  O1  Is it an image or other auto-loaded reference to a host that only
      untrusted content named? An image loads with no click, so this is
      blocked.
  O2  Does the address carry a piece of sensitive content (a token or a
      long span copied from a sensitive item) to a host the user did not
      name? Blocked, image or link.

A link to a host that only untrusted content named, with no sensitive
data in it, is reported as a warning and left in place.

Limits: it only reads the text it is given, it knows secrets only when
they were ingested as sensitive content, and a secret that is split or
re-encoded in a way the readings in normalize.py do not undo can slip
through. It does not stop a client that renders things the text does not
show.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote

from .taint import TaintTracker as Tracker, entity_for, shared_span

IMAGE = re.compile(r'!\[[^\]]*\]\(\s*<?([^)\s>]+)')
LINK = re.compile(r'(?<!!)\[[^\]]*\]\(\s*<?([^)\s>]+)')
BARE = re.compile(r'https?://[^\s\'"<>)\]]+', re.IGNORECASE)
HTML_SRC = re.compile(
    r'<(?:img|iframe|script|link)[^>]+(?:src|href)\s*=\s*["\']?([^"\'\s>]+)',
    re.IGNORECASE,
)
SECRET_TOKEN = re.compile(r'[A-Za-z0-9_\-]{8,}')


@dataclass
class OutputFinding:
    """One suspicious reference in an answer."""

    rule_id: str
    verdict: str  # 'block' or 'warn'
    url: str
    reason: str


@dataclass
class OutputCheck:
    """Result of checking one answer."""

    verdict: str  # 'allow' or 'block'
    findings: list[OutputFinding] = field(default_factory=list)
    safe_text: str = ''


def _looks_secret(token: str) -> bool:
    """A long token with digits and letters, or a very long token."""
    has_digit = any(c.isdigit() for c in token)
    has_alpha = any(c.isalpha() for c in token)
    return (has_digit and has_alpha and len(token) >= 8) or len(token) >= 20


def carries_sensitive(url: str, tracker: Tracker) -> str | None:
    """Return the piece of sensitive content found inside an address."""
    decoded = unquote(unquote(url))
    for item in tracker.sensitive_items():
        span = shared_span(decoded, item.text)
        if span is not None:
            return span
        lowered = decoded.lower()
        for token in SECRET_TOKEN.findall(item.text):
            if _looks_secret(token) and token.lower() in lowered:
                return token
    return None


def check_text(text: str, tracker: Tracker) -> OutputCheck:
    """Inspect an answer and return findings plus a version without them."""
    images = set(IMAGE.findall(text)) | set(HTML_SRC.findall(text))
    links = set(LINK.findall(text))
    bare = set(BARE.findall(text))
    findings: list[OutputFinding] = []
    flagged: set[str] = set()

    for url in sorted(images | links | bare):
        if not url.lower().startswith(('http://', 'https://', '//')):
            continue
        if tracker.is_user_authorized(url):
            continue
        is_image = url in images
        origin = tracker.untrusted_origin(url)
        leaked = carries_sensitive(url, tracker)
        host = entity_for(url if '://' in url else 'https:' + url)

        if leaked is not None:
            findings.append(OutputFinding(
                'O2', 'block', url,
                'address to "' + host + '" carries sensitive content',
            ))
            flagged.add(url)
        elif is_image and origin is not None:
            findings.append(OutputFinding(
                'O1', 'block', url,
                'image from "' + host + '", named only by untrusted '
                'content, would load without a click',
            ))
            flagged.add(url)
        elif origin is not None:
            findings.append(OutputFinding(
                'O0', 'warn', url,
                'link to "' + host + '", named only by untrusted content',
            ))

    safe = text
    for url in flagged:
        safe = safe.replace(url, '[removed by AgentGuard]')
    blocked = any(f.verdict == 'block' for f in findings)
    return OutputCheck('block' if blocked else 'allow', findings, safe)
