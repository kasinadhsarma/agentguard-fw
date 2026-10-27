"""ToolGuard: the one-line wrapper between an agent loop and its tools.

    from agentguard.adapters import ToolGuard

    guard = ToolGuard.local('Summarize the page and email boss@acme.test')
    tools = guard.protect_all({'fetch_page': fetch_page, 'send_email': send})

Every call made through a protected tool is authorized first, and every
result is recorded as untrusted content before the model sees it. A
call the firewall blocks raises ToolBlocked (or, in message mode, returns
a short refusal the model can read and react to). A call that needs
confirmation is passed to on_confirm; with no callback it is refused.

ToolGuard works with a local Firewall object. To use the HTTP proxy
instead, call its endpoints from your own loop; the logic is the same.
"""

from __future__ import annotations

import functools
import inspect
import json
from typing import Any, Callable

from ..firewall import Firewall
from ..models import Decision, ToolRisk, Verdict


ConfirmFn = Callable[[Decision], bool]


class ToolBlocked(PermissionError):
    """Raised when the firewall refuses a tool call."""

    def __init__(self, decision: Decision, confirmed: bool = False) -> None:
        """Remember the decision that caused the refusal."""
        self.decision = decision
        self.confirmed = confirmed
        super().__init__(refusal_message(decision, confirmed))


def refusal_message(decision: Decision, confirmed: bool = False) -> str:
    """Text a model can read after a call was refused."""
    if decision.verdict == Verdict.CONFIRM and not confirmed:
        prefix = 'NOT RUN: the user did not approve this action'
    else:
        prefix = 'BLOCKED by AgentGuard'
    return (
        prefix + ' [' + decision.rule_id + ']: ' + decision.reason +
        '. Do not retry this action.'
    )


def result_to_text(result: Any) -> str:
    """Turn a tool result into the text that is scanned and recorded."""
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, default=str)
    except (TypeError, ValueError):
        return str(result)


class ToolGuard:
    """Holds one firewall session and guards calls made through it."""

    def __init__(
        self,
        firewall: Firewall,
        user_prompt: str = '',
        on_confirm: ConfirmFn | None = None,
        session_id: str | None = None,
    ) -> None:
        """Wrap a firewall; opens a session unless one is given."""
        self.firewall = firewall
        self.on_confirm = on_confirm
        self.session_id = session_id or firewall.new_session(user_prompt)
        self.decisions: list[Decision] = []

    @classmethod
    def local(
        cls,
        user_prompt: str,
        on_confirm: ConfirmFn | None = None,
        **firewall_options: Any,
    ) -> 'ToolGuard':
        """Create a guard with a fresh in-process Firewall."""
        return cls(Firewall(**firewall_options), user_prompt, on_confirm)

    def register_tools(self, definitions: list[dict]) -> list[dict]:
        """Register framework tool definitions (schemas, profiles)."""
        return self.firewall.policy.config.register_tools(definitions)

    def model_said(self, text: str) -> None:
        """Record text the model wrote, so derived taint is tracked."""
        if text and text.strip():
            self.firewall.record_model_output(self.session_id, text)

    def check(self, tool: str, args: dict[str, Any]) -> Decision:
        """Ask the firewall about a call without running anything."""
        decision = self.firewall.authorize(self.session_id, tool, args)
        self.decisions.append(decision)
        return decision

    def observe(self, tool: str, result: Any) -> None:
        """Record a tool result as untrusted content.

        Results of tools profiled as sensitive reads are also marked
        sensitive, so they can never be copied out (rule R2) or sent to
        the external judge.
        """
        profile = self.firewall.policy.profile_for(tool)
        self.firewall.ingest(
            self.session_id,
            result_to_text(result),
            source='tool:' + tool,
            sensitive=profile.risk == ToolRisk.SENSITIVE_READ,
        )

    def permit(self, tool: str, args: dict[str, Any]) -> None:
        """Authorize a call or raise ToolBlocked."""
        decision = self.check(tool, args)
        if decision.verdict == Verdict.ALLOW:
            return
        if decision.verdict == Verdict.CONFIRM:
            if self.on_confirm is not None and self.on_confirm(decision):
                return
            raise ToolBlocked(decision)
        raise ToolBlocked(decision, confirmed=True)

    def run(
        self,
        tool: str,
        args: dict[str, Any],
        function: Callable[..., Any],
        on_block: str = 'raise',
    ) -> Any:
        """Authorize, run function(**args), record the result, return it.

        on_block is 'raise' (ToolBlocked) or 'message' (return refusal text).
        """
        try:
            self.permit(tool, args)
        except ToolBlocked as blocked:
            if on_block == 'message':
                return str(blocked)
            raise
        result = function(**args)
        self.observe(tool, result)
        return result

    async def arun(
        self,
        tool: str,
        args: dict[str, Any],
        function: Callable[..., Any],
        on_block: str = 'raise',
    ) -> Any:
        """Async version of run() for coroutine tools."""
        try:
            self.permit(tool, args)
        except ToolBlocked as blocked:
            if on_block == 'message':
                return str(blocked)
            raise
        result = await function(**args)
        self.observe(tool, result)
        return result

    def protect(
        self,
        function: Callable[..., Any],
        name: str | None = None,
        on_block: str = 'raise',
    ) -> Callable[..., Any]:
        """Return a guarded version of a plain function (sync or async)."""
        tool = name or function.__name__
        signature = inspect.signature(function)

        def bind(args: tuple, kwargs: dict) -> dict[str, Any]:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            return dict(bound.arguments)

        if inspect.iscoroutinefunction(function):
            @functools.wraps(function)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return await self.arun(
                    tool, bind(args, kwargs), function, on_block,
                )
            return async_wrapper

        @functools.wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return self.run(tool, bind(args, kwargs), function, on_block)
        return wrapper

    def protect_all(
        self,
        tools: dict[str, Callable[..., Any]],
        on_block: str = 'raise',
    ) -> dict[str, Callable[..., Any]]:
        """Guard a name -> function mapping."""
        return {
            name: self.protect(function, name, on_block)
            for name, function in tools.items()
        }
