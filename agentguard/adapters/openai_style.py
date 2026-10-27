"""Adapter for OpenAI-style chat tool calls.

Works with plain dictionaries and with SDK objects (anything exposing
.id and .function.name / .function.arguments), and needs no OpenAI
package.

    messages.append(assistant_message)
    guard.model_said(content_of(assistant_message))
    messages += run_tool_calls(guard, assistant_message['tool_calls'], handlers)

Each returned message is {"role": "tool", "tool_call_id": ..., "content": ...},
ready to append to the conversation. Refused calls come back as a message
that says so; the handler is never called for them.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .base import ToolBlocked, ToolGuard, result_to_text


def _field(source: Any, name: str, default: Any = None) -> Any:
    """Read a field from a dict or an attribute from an object."""
    if isinstance(source, dict):
        return source.get(name, default)
    return getattr(source, name, default)


def content_of(message: Any) -> str:
    """Return the text content of an assistant message, or ''."""
    content = _field(message, 'content', '')
    return content if isinstance(content, str) else ''


def run_tool_calls(
    guard: ToolGuard,
    tool_calls: list[Any] | None,
    handlers: dict[str, Callable[..., Any]],
) -> list[dict[str, str]]:
    """Authorize and run each tool call, returning tool messages."""
    messages: list[dict[str, str]] = []
    for call in tool_calls or []:
        call_id = str(_field(call, 'id', ''))
        function = _field(call, 'function')
        name = str(_field(function, 'name', ''))
        raw = _field(function, 'arguments', '{}') or '{}'

        def reply(text: str) -> None:
            messages.append(
                {'role': 'tool', 'tool_call_id': call_id, 'content': text},
            )

        try:
            args = json.loads(raw) if isinstance(raw, str) else dict(raw)
            if not isinstance(args, dict):
                raise ValueError('arguments must be an object')
        except (ValueError, TypeError):
            reply('ERROR: the arguments were not a valid JSON object')
            continue

        handler = handlers.get(name)
        if handler is None:
            reply('ERROR: unknown tool "' + name + '"')
            continue

        try:
            reply(result_to_text(guard.run(name, args, handler)))
        except ToolBlocked as blocked:
            reply(str(blocked))
    return messages
