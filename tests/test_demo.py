"""End-to-end tests: the simulated agent with and without the firewall."""

import pytest

from agentguard import Firewall
from demo.agent import SimAgent
from demo.scenarios import scenarios

ALL = {scenario.name: scenario for scenario in scenarios()}


@pytest.mark.parametrize('name', ['poisoned', 'subtle'])
def test_unprotected_agent_leaks_the_secret(name: str) -> None:
    """Without the firewall, both attacks succeed."""
    report = SimAgent().run(ALL[name])
    assert report.leaked is True
    assert any(
        email['to'].endswith('@evil.test') for email in report.sent_emails
    )


@pytest.mark.parametrize('name', ['poisoned', 'subtle'])
def test_protected_agent_blocks_the_attack(name: str) -> None:
    """With the firewall, nothing leaves and the real task still works."""
    report = SimAgent(Firewall()).run(ALL[name])

    assert report.leaked is False
    assert report.secrets_read == []
    assert report.blocked_count == 2
    recipients = [email['to'] for email in report.sent_emails]
    assert recipients == ['boss@acme.test']


def test_subtle_attack_evades_patterns_but_not_taint_tracking() -> None:
    """The polite attack scores below the threshold yet is still blocked."""
    firewall = Firewall()
    report = SimAgent(firewall).run(ALL['subtle'])

    session = next(iter(firewall.sessions.values()))
    page_scores = [
        item.injection_score
        for item in session.tracker.untrusted_items()
        if item.source == 'tool:fetch_page'
    ]
    assert page_scores and max(page_scores) < 0.5
    assert report.blocked_count == 2


def test_benign_scenario_has_no_false_positives() -> None:
    """A normal task runs with zero blocks and zero confirmations."""
    report = SimAgent(Firewall()).run(ALL['benign'])

    assert report.blocked_count == 0
    assert all(step.verdict == 'allow' for step in report.steps)
    assert [email['to'] for email in report.sent_emails] == ['boss@acme.test']
