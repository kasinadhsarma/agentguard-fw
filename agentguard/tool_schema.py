"""Tool definitions: schemas, argument validation and generated profiles.

Agent frameworks already describe their tools with a name and a JSON
Schema for the arguments (OpenAI "tools", Anthropic and MCP "input
schema"). This module reads those definitions and does two jobs:

  1. generate a risk profile (read, sensitive read, side effect, and
     which arguments name the target) so a new tool does not need a
     hand-written entry;
  2. validate a proposed call against the schema, so malformed or
     unexpected arguments are caught before the tool sees them.

Generated profiles are heuristics. They look only at the tool NAME and
the argument NAMES and formats, never at the free-text description,
because descriptions can come from third-party servers and may be
written by an attacker ("tool poisoning"). A tool whose name gives no
signal is treated as a side effect (fail closed). Profiles that were
written by hand always win over generated ones.

Supported JSON Schema subset: type, enum, required, properties,
additionalProperties (false), items, minLength, maxLength, minimum,
maximum, pattern and the "email" format. Other keywords are ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .models import ToolRisk


# verbs that change the world: any one in the tool name makes it risky
SIDE_EFFECT_VERBS = frozenset({
    'send', 'post', 'put', 'patch', 'delete', 'remove', 'write', 'create',
    'update', 'exec', 'execute', 'run', 'shell', 'command', 'transfer',
    'pay', 'upload', 'publish', 'drop', 'move', 'rename', 'commit', 'push',
    'deploy', 'email', 'mail', 'message', 'reply', 'forward', 'share',
    'invite', 'grant', 'revoke', 'kill', 'install', 'uninstall', 'submit',
    'book', 'purchase', 'buy', 'order', 'edit', 'set', 'save', 'append',
    'insert', 'clear', 'reset', 'wipe', 'format', 'chmod', 'chown',
})

# verbs that only read
READ_VERBS = frozenset({
    'fetch', 'get', 'search', 'list', 'browse', 'query', 'view', 'find',
    'lookup', 'read', 'open', 'load', 'cat', 'show', 'download', 'scrape',
    'crawl', 'check', 'describe', 'summarize', 'extract', 'inspect',
    'retrieve', 'dump', 'export', 'tail', 'head',
})

# objects whose contents are private even when only read
SENSITIVE_OBJECTS = frozenset({
    'file', 'files', 'secret', 'secrets', 'credential', 'credentials',
    'password', 'passwords', 'token', 'tokens', 'key', 'keys', 'env',
    'mail', 'mails', 'email', 'emails', 'inbox', 'database', 'db',
    'record', 'records', 'document', 'documents', 'doc', 'docs', 'note',
    'notes', 'vault', 'wallet', 'account', 'contact', 'contacts',
    'history', 'log', 'logs', 'config', 'settings',
})

# argument names that point at a file
PATH_ARGUMENTS = frozenset({
    'path', 'filepath', 'file', 'filename', 'directory', 'dir', 'folder',
})

# argument names that point at a recipient or a destination
RECIPIENT_ARGUMENTS = frozenset({
    'to', 'cc', 'bcc', 'recipient', 'recipients', 'email', 'emails',
    'webhook', 'destination', 'dest',
})

# words in an argument name that mean "send the result somewhere"
OUTBOUND_WORDS = frozenset({'callback', 'webhook', 'forward', 'notify'})

# every argument name that can name who or what a call affects
TARGET_ARGUMENTS = PATH_ARGUMENTS | RECIPIENT_ARGUMENTS | frozenset({
    'address', 'url', 'uri', 'endpoint', 'host', 'hostname', 'domain',
    'command', 'cmd', 'script', 'target', 'channel',
})

# single words that mark a target when they are part of a longer name
# (callback_url, output_path); ambiguous words like "to" are excluded
TARGET_WORDS = TARGET_ARGUMENTS - frozenset({
    'to', 'address', 'target', 'channel', 'dest',
})

TARGET_FORMATS = frozenset({
    'email', 'idn-email', 'uri', 'uri-reference', 'url', 'hostname',
})

# explicit marker a schema author can put on a property
TARGET_MARKER = 'x-agentguard-target'

MAX_SCHEMA_DEPTH = 5

EMAIL_SHAPE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


@dataclass
class ToolSpec:
    """One tool as its framework describes it."""

    name: str
    description: str = ''
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class GeneratedProfile:
    """The risk class and target arguments inferred for a tool."""

    risk: ToolRisk
    target_args: tuple[str, ...]
    reason: str


def parse_tool_definitions(
    definitions: list[dict[str, Any]],
) -> list[ToolSpec]:
    """Read tool definitions in any of the common shapes.

    Accepted shapes:
      {"type": "function", "function": {"name", "description", "parameters"}}
      {"name", "description", "input_schema"}      (Anthropic)
      {"name", "description", "inputSchema"}       (MCP)
      {"name", "description", "parameters"}        (plain)
    """
    specs: list[ToolSpec] = []
    for raw in definitions:
        if not isinstance(raw, dict):
            raise ValueError('a tool definition must be an object')
        nested = raw.get('function')
        body = nested if isinstance(nested, dict) else raw
        name = body.get('name')
        if not isinstance(name, str) or not name.strip():
            raise ValueError('a tool definition needs a non-empty name')

        schema = (
            body.get('parameters')
            or body.get('input_schema')
            or body.get('inputSchema')
            or {}
        )
        if not isinstance(schema, dict):
            raise ValueError('parameters of "' + name + '" must be an object')
        specs.append(
            ToolSpec(
                name=name.strip(),
                description=str(body.get('description', '')),
                parameters=schema,
            )
        )
    return specs


def name_tokens(name: str) -> list[str]:
    """Split snake_case, kebab-case, dotted and camelCase names."""
    spaced = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', name)
    return [t for t in re.split(r'[^A-Za-z0-9]+', spaced.lower()) if t]


def property_schemas(parameters: dict[str, Any]) -> dict[str, dict]:
    """Return the top-level property schemas of a parameters object."""
    properties = parameters.get('properties', {})
    return {
        key: value
        for key, value in properties.items()
        if isinstance(value, dict)
    }


def find_target_args(parameters: dict[str, Any]) -> tuple[str, ...]:
    """Find the arguments that name who or what a call affects."""
    found: list[str] = []
    for name, schema in property_schemas(parameters).items():
        items = schema.get('items')
        items = items if isinstance(items, dict) else {}
        by_name = name.lower() in TARGET_ARGUMENTS or bool(
            set(name_tokens(name)) & TARGET_WORDS
        )
        by_format = (
            schema.get('format') in TARGET_FORMATS
            or items.get('format') in TARGET_FORMATS
        )
        by_marker = bool(schema.get(TARGET_MARKER))
        if by_name or by_format or by_marker:
            found.append(name)
    return tuple(found)


def infer_profile(spec: ToolSpec) -> GeneratedProfile:
    """Infer a risk class and target arguments from names and formats."""
    tokens = set(name_tokens(spec.name))
    targets = find_target_args(spec.parameters)
    argument_names = {
        name.lower() for name in property_schemas(spec.parameters)
    }

    side = tokens & SIDE_EFFECT_VERBS
    if side:
        return GeneratedProfile(
            ToolRisk.SIDE_EFFECT, targets,
            'name contains the side-effect verb "' + sorted(side)[0] + '"',
        )

    read = tokens & READ_VERBS
    if read:
        # a "read" tool that takes a recipient or callback is sending data
        argument_words = {
            word for name in argument_names for word in name_tokens(name)
        }
        if argument_names & RECIPIENT_ARGUMENTS or (
            argument_words & OUTBOUND_WORDS
        ):
            return GeneratedProfile(
                ToolRisk.SIDE_EFFECT, targets,
                'read-style name but it takes a recipient or callback',
            )
        private = (tokens & SENSITIVE_OBJECTS) or (
            argument_names & PATH_ARGUMENTS
        )
        if private:
            return GeneratedProfile(
                ToolRisk.SENSITIVE_READ, targets,
                'reads a private object (' + ', '.join(sorted(private)) + ')',
            )
        return GeneratedProfile(
            ToolRisk.READ, targets,
            'name contains the read verb "' + sorted(read)[0] + '"',
        )

    return GeneratedProfile(
        ToolRisk.SIDE_EFFECT, targets,
        'no recognizable verb in the name, so it fails closed',
    )


def _type_matches(value: Any, expected: str) -> bool:
    """Check one JSON Schema type name against a Python value."""
    if expected == 'string':
        return isinstance(value, str)
    if expected == 'boolean':
        return isinstance(value, bool)
    if expected == 'integer':
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == 'number':
        return (
            isinstance(value, (int, float)) and not isinstance(value, bool)
        )
    if expected == 'array':
        return isinstance(value, list)
    if expected == 'object':
        return isinstance(value, dict)
    if expected == 'null':
        return value is None
    return True


def _check_value(
    value: Any,
    schema: dict[str, Any],
    where: str,
    depth: int,
) -> list[str]:
    """Validate one value against one property schema."""
    problems: list[str] = []

    expected = schema.get('type')
    if expected is not None:
        allowed = expected if isinstance(expected, list) else [expected]
        if not any(_type_matches(value, kind) for kind in allowed):
            return [where + ': expected ' + '/'.join(map(str, allowed))]

    if 'enum' in schema and value not in schema['enum']:
        problems.append(where + ': not one of the allowed values')

    if isinstance(value, str):
        if len(value) > schema.get('maxLength', len(value)):
            problems.append(where + ': longer than maxLength')
        if len(value) < schema.get('minLength', 0):
            problems.append(where + ': shorter than minLength')
        pattern = schema.get('pattern')
        if isinstance(pattern, str):
            try:
                if not re.search(pattern, value):
                    problems.append(where + ': does not match pattern')
            except re.error:
                pass
        if schema.get('format') in ('email', 'idn-email'):
            if not EMAIL_SHAPE.match(value):
                problems.append(where + ': not an e-mail address')

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema.get('minimum', value):
            problems.append(where + ': below minimum')
        if value > schema.get('maximum', value):
            problems.append(where + ': above maximum')

    if isinstance(value, list) and isinstance(schema.get('items'), dict):
        for index, entry in enumerate(value):
            problems += _check_value(
                entry, schema['items'], where + '[' + str(index) + ']', depth,
            )

    if isinstance(value, dict) and depth < MAX_SCHEMA_DEPTH:
        problems += _check_object(value, schema, where, depth + 1)
    return problems


def _check_object(
    arguments: dict[str, Any],
    schema: dict[str, Any],
    where: str,
    depth: int,
) -> list[str]:
    """Validate an object's required keys, extra keys and properties."""
    problems: list[str] = []
    properties = property_schemas(schema)
    prefix = where + '.' if where else ''

    for name in schema.get('required', []):
        if name not in arguments:
            problems.append(prefix + str(name) + ': required argument missing')

    if schema.get('additionalProperties') is False:
        for name in arguments:
            if name not in properties:
                problems.append(prefix + str(name) + ': unexpected argument')

    for name, value in arguments.items():
        if name in properties:
            problems += _check_value(
                value, properties[name], prefix + str(name), depth,
            )
    return problems


def validate_arguments(
    spec: ToolSpec,
    arguments: dict[str, Any],
) -> list[str]:
    """Return the problems found in a call's arguments (empty if valid)."""
    if not spec.parameters:
        return []
    return _check_object(arguments, spec.parameters, '', 0)
