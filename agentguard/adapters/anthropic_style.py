"""Adapter for Anthropic-style tool use blocks.

Works with plain dictionaries and with SDK objects (anything exposing
.type, .id, .name and .input), and needs no Anthropic package.

    guard.model_said(text_of(response.content))
    results = run_tool_uses(guard, response.content, handlers)
    messages.append({"role": "user", "content": results})

Each result is a tool_result block with is_error set for refused calls.
"""

from __future__ import annotations

from typing import Any, Callable

from .base import ToolBlocked, ToolGuard, result_to_text
from .openai_style import _field


def text_of(blocks: list[Any]) -> str:
    """Join the text blocks of an assistant turn."""
    parts = [
        str(_field(block, 'text', ''))
        for block in blocks or []
        if _field(block, 'type') == 'text'
    ]
    return '\n'.join(part for part in parts if part)


def run_tool_uses(
    guard: ToolGuard,
    blocks: list[Any],
    handlers: dict[str, Callable[..., Any]],
) -> list[dict[str, Any]]:
    """Authorize and run each tool_use block, returning tool_result blocks."""
    results: list[dict[str, Any]] = []
    for block in blocks or []:
        if _field(block, 'type') != 'tool_use':
            continue
        use_id = str(_field(block, 'id', ''))
        name = str(_field(block, 'name', ''))
        args = _field(block, 'input', {}) or {}

        def reply(text: str, error: bool) -> None:
            results.append({
                'type': 'tool_result',
                'tool_use_id': use_id,
                'content': text,
                'is_error': error,
            })

        handler = handlers.get(name)
        if handler is None or not isinstance(args, dict):
            reply('ERROR: unknown tool or bad input for "' + name + '"', True)
            continue

        try:
            reply(result_to_text(guard.run(name, dict(args), handler)), False)
        except ToolBlocked as blocked:
            reply(str(blocked), True)
    return results
