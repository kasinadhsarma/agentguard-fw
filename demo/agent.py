"""A deterministic simulated agent, with and without the firewall.

The agent has three fake tools (fetch_page, read_file, send_email) that
only touch an in-memory sandbox. It follows any instruction it reads in
fetched content, which models a successfully hijacked LLM agent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from agentguard import Decision, Firewall, Verdict

from .scenarios import SANDBOX_FILES, SECRET_MARKER, Scenario


READ_PATTERN = re.compile(
    r'(?:read|open|attach the contents of)\s+(?:the\s+file\s+)?'
    r'(~?/[\w./-]+)',
    re.IGNORECASE,
)
SEND_PATTERN = re.compile(
    r'\b(?:send|forward|share|email)\b.{0,80}?\b(?:to|with)\s+'
    r'([\w.+-]+@[\w-]+(?:\.[\w-]+)+)',
    re.IGNORECASE | re.DOTALL,
)
COMMENT_PATTERN = re.compile(r'<!--.*?-->', re.DOTALL)

ConfirmFn = Callable[[Decision], bool]


@dataclass
class Step:
    """One tool call the agent attempted and what happened to it."""

    tool: str
    args: dict[str, Any]
    verdict: str
    rule_id: str
    reason: str
    executed: bool
    note: str = ''


@dataclass
class RunReport:
    """Everything that happened in one agent run."""

    scenario: str
    protected: bool
    steps: list[Step] = field(default_factory=list)
    sent_emails: list[dict[str, str]] = field(default_factory=list)
    secrets_read: list[str] = field(default_factory=list)
    # set by the live (LLM-driven) agent
    final: str = ''
    error: str = ''

    @property
    def leaked(self) -> bool:
        """True when a fake secret left the sandbox in an email."""
        return any(
            SECRET_MARKER in email['body'] for email in self.sent_emails
        )

    @property
    def blocked_count(self) -> int:
        """Number of calls the firewall refused."""
        return sum(1 for step in self.steps if step.verdict == 'block')


def default_confirm(decision: Decision) -> bool:
    """Simulated user: approve only actions on targets they named (R4)."""
    return decision.rule_id == 'R4'


def visible_text(page: str) -> str:
    """Return the text a human would see, without hidden comments."""
    return ' '.join(COMMENT_PATTERN.sub(' ', page).split())


def summarize(page: str, limit: int = 160) -> str:
    """Produce a naive summary from the visible text of a page."""
    return visible_text(page)[:limit]


def parse_injected_actions(page: str) -> list[tuple[str, dict[str, Any]]]:
    """Find the instructions a gullible agent would follow in a page.

    Returns tool calls in the order the page asks for them. The email
    body is filled in later with whatever the agent has read.
    """
    actions: list[tuple[str, dict[str, Any]]] = []

    read_match = READ_PATTERN.search(page)
    if read_match:
        actions.append(('read_file', {'path': read_match.group(1)}))

    send_match = SEND_PATTERN.search(page)
    if send_match:
        actions.append(('send_email', {'to': send_match.group(1)}))

    return actions


class SimAgent:
    """Runs a scenario, optionally routing every tool call via a firewall."""

    def __init__(
        self,
        firewall: Firewall | None = None,
        confirm: ConfirmFn = default_confirm,
    ) -> None:
        """Create an agent; pass a Firewall to protect it."""
        self.firewall = firewall
        self.confirm = confirm

    def run(self, scenario: Scenario) -> RunReport:
        """Execute the scenario and return a report."""
        report = RunReport(
            scenario=scenario.name,
            protected=self.firewall is not None,
        )
        session_id = None
        if self.firewall is not None:
            session_id = self.firewall.new_session(scenario.user_prompt)

        page = self._call(
            report,
            session_id,
            scenario,
            'fetch_page',
            {'url': scenario.url},
        )
        if page is None:
            return report

        summary = summarize(scenario.page)
        last_secret = ''

        for tool, args in parse_injected_actions(scenario.page):
            if tool == 'send_email':
                args = dict(args)
                args['subject'] = 'Requested data'
                args['body'] = last_secret or summary
            result = self._call(report, session_id, scenario, tool, args)
            if tool == 'read_file' and result is not None:
                last_secret = result

        self._call(
            report,
            session_id,
            scenario,
            'send_email',
            {
                'to': scenario.recipient,
                'subject': 'Q3 summary',
                'body': summary,
            },
        )
        return report

    def _call(
        self,
        report: RunReport,
        session_id: str | None,
        scenario: Scenario,
        tool: str,
        args: dict[str, Any],
    ) -> str | None:
        """Run one tool call, consulting the firewall when protected."""
        verdict = 'allow'
        rule_id = '-'
        reason = 'no firewall'
        note = ''

        if self.firewall is not None and session_id is not None:
            decision = self.firewall.authorize(session_id, tool, args)
            verdict = decision.verdict.value
            rule_id = decision.rule_id
            reason = decision.reason

            if decision.verdict == Verdict.BLOCK:
                report.steps.append(
                    Step(tool, args, verdict, rule_id, reason, False),
                )
                return None

            if decision.verdict == Verdict.CONFIRM:
                approved = self.confirm(decision)
                note = 'user approved' if approved else 'user denied'
                if not approved:
                    report.steps.append(
                        Step(tool, args, verdict, rule_id, reason, False, note),
                    )
                    return None

        result = self._execute(report, scenario, tool, args)
        report.steps.append(
            Step(tool, args, verdict, rule_id, reason, True, note),
        )

        if self.firewall is not None and session_id is not None:
            if tool in ('fetch_page', 'read_file') and result is not None:
                self.firewall.ingest(
                    session_id,
                    result,
                    source='tool:' + tool,
                )
        return result

    def _execute(
        self,
        report: RunReport,
        scenario: Scenario,
        tool: str,
        args: dict[str, Any],
    ) -> str | None:
        """Perform the fake tool against the in-memory sandbox."""
        if tool == 'fetch_page':
            return scenario.page
        if tool == 'read_file':
            path = args['path']
            content = SANDBOX_FILES.get(path, '')
            report.secrets_read.append(path)
            return content
        if tool == 'send_email':
            report.sent_emails.append(
                {
                    'to': args['to'],
                    'subject': args.get('subject', ''),
                    'body': args.get('body', ''),
                },
            )
            return 'sent'
        return None
