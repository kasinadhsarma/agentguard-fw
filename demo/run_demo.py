"""Command-line demo: the same agent, unprotected and then protected.

Run from the project root:

    python -m demo.run_demo

Set MODEL_API_KEY to also enable the Meta Model API LLM judge.

    python -m demo.run_demo --live

runs a real model (through the Meta Model API) as the agent instead of the
deterministic simulation. The model may or may not follow the injection.
"""

from __future__ import annotations

import argparse
import sys

from agentguard import Firewall, MetaJudge

from .agent import RunReport, SimAgent
from .live_agent import LiveAgent
from .scenarios import scenarios


GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BOLD = '\033[1m'
RESET = '\033[0m'


def verdict_label(step) -> str:
    """Color a step's verdict for the terminal."""
    if step.verdict == 'block':
        return RED + 'BLOCKED' + RESET
    if step.verdict == 'confirm':
        return YELLOW + 'CONFIRM (' + (step.note or 'held') + ')' + RESET
    return GREEN + 'ok' + RESET


def print_report(report: RunReport) -> None:
    """Print one run in a readable form."""
    mode = 'PROTECTED' if report.protected else 'UNPROTECTED'
    print(BOLD + '  [' + mode + ']' + RESET)
    for step in report.steps:
        target = step.args.get('to') or step.args.get('path') or step.args.get('url')
        line = '    ' + step.tool + '(' + str(target) + ')  ->  '
        print(line + verdict_label(step))
        if step.verdict == 'block':
            print('      ' + step.rule_id + ': ' + step.reason)
    if report.error:
        print(YELLOW + '    NOTE: ' + report.error + RESET)
    if report.final:
        print('    model said: ' + report.final[:100])
    if report.leaked:
        print(RED + BOLD + '    RESULT: secret leaked to attacker' + RESET)
    elif report.protected:
        print(GREEN + BOLD + '    RESULT: no data left the sandbox' + RESET)
    else:
        print(GREEN + '    RESULT: nothing leaked' + RESET)


def run_live() -> int:
    """Run every scenario with a real model, with and without the firewall."""
    live = LiveAgent()
    if not live.enabled:
        print('--live needs the MODEL_API_KEY environment variable.')
        return 2

    judge = MetaJudge()
    print('Live agent model: ' + live.model + ' (results can vary per run)')
    for scenario in scenarios():
        print('\n' + BOLD + scenario.title + RESET)
        print_report(LiveAgent().run(scenario))
        firewall = Firewall(judge=judge if judge.enabled else None)
        print_report(LiveAgent(firewall).run(scenario))
    return 0


def main() -> None:
    """Run every scenario with and without the firewall."""
    parser = argparse.ArgumentParser(description='AgentGuard demo')
    parser.add_argument('--live', action='store_true',
                        help='use a real model through the Meta Model API')
    if parser.parse_args().live:
        sys.exit(run_live())

    judge = MetaJudge()
    firewall_judge = judge if judge.enabled else None
    print(
        'LLM judge: ' +
        ('on (' + judge.model + ')' if judge.enabled else 'off (heuristics only)')
    )

    for scenario in scenarios():
        print('\n' + BOLD + scenario.title + RESET)
        print('  ' + scenario.description)
        print_report(SimAgent().run(scenario))
        guarded = SimAgent(Firewall(judge=firewall_judge))
        print_report(guarded.run(scenario))


if __name__ == '__main__':
    main()
