"""Adapter for LangChain tools (langchain-core).

    from agentguard.adapters import ToolGuard
    from agentguard.adapters.langchain import protect_langchain_tools

    guard = ToolGuard.local(user_request)
    safe_tools = protect_langchain_tools(tools, guard)

The returned tools keep each original tool's name, description and
argument schema, so they drop into any agent that accepts LangChain
tools. A refused call returns a short refusal string instead of raising,
so the agent can read it and carry on. langchain-core is imported only
when this module is used.
"""

from __future__ import annotations

from typing import Any

from .base import ToolGuard


def _definition(tool: Any) -> dict[str, Any]:
    """Describe a LangChain tool as a framework-neutral definition."""
    schema = getattr(tool, 'args_schema', None)
    parameters: dict[str, Any] = {}
    if schema is not None and hasattr(schema, 'model_json_schema'):
        parameters = schema.model_json_schema()
    elif isinstance(schema, dict):
        parameters = schema
    return {
        'name': tool.name,
        'description': getattr(tool, 'description', ''),
        'parameters': parameters,
    }


def protect_langchain_tools(
    tools: list[Any],
    guard: ToolGuard,
    register: bool = True,
) -> list[Any]:
    """Wrap LangChain tools so every call goes through the firewall.

    With register=True the tools' argument schemas are also registered,
    which generates risk profiles for tools the policy does not know and
    turns on schema validation (rule R5).
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as error:
        raise ImportError(
            'protect_langchain_tools needs langchain-core: '
            'pip install langchain-core'
        ) from error

    if register:
        guard.register_tools([_definition(tool) for tool in tools])

    return [_wrap(StructuredTool, tool, guard) for tool in tools]


def _wrap(structured_tool: Any, tool: Any, guard: ToolGuard) -> Any:
    """Build one guarded StructuredTool around an existing tool."""

    def run(**arguments: Any) -> Any:
        return guard.run(
            tool.name, arguments,
            lambda **args: tool.invoke(args),
            on_block='message',
        )

    async def arun(**arguments: Any) -> Any:
        async def call(**args: Any) -> Any:
            return await tool.ainvoke(args)
        return await guard.arun(
            tool.name, arguments, call, on_block='message',
        )

    return structured_tool.from_function(
        func=run,
        coroutine=arun,
        name=tool.name,
        description=getattr(tool, 'description', '') or tool.name,
        args_schema=getattr(tool, 'args_schema', None),
    )
