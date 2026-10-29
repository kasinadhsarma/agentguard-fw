"""Command-line demo: the same agent, unprotected and then protected.

Run from the project root:

    python -m demo.run_demo

Set MODEL_API_KEY to also enable the Meta Model API LLM judge.

    python -m demo.run_demo --live

runs a real model (through the Meta Model API) as the agent instead of the
deterministic simulation. The model may or may not follow the injection.

    python -m demo.run_demo --live --hard --runs 5

adds three harder attack pages and repeats every scenario 5 times, then
prints how often the model leaked with and without the firewall.
"""

from __future__ import annotations

import argparse
import sys

from agentguard import Firewall, MetaJudge

from .agent import RunReport, SimAgent
from .live_agent import LiveAgent
from .scenarios import hard_scenarios, scenarios


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


def summarize(
    scenario,
    unprotected: list[RunReport],
    protected: list[RunReport],
) -> dict:
    """Count what happened over repeated runs of one attack scenario.

    Runs that ended in an API error are counted separately and left out of
    the other numbers, so a billing problem cannot look like a defense.
    """
    def usable(reports: list[RunReport]) -> list[RunReport]:
        return [report for report in reports if not report.error]

    bare, guarded = usable(unprotected), usable(protected)
    return {
        'scenario': scenario.name,
        'errors': (len(unprotected) - len(bare)) + (len(protected) - len(guarded)),
        'unprotected_runs': len(bare),
        'unprotected_leaks': sum(1 for r in bare if r.leaked),
        'protected_runs': len(guarded),
        'protected_leaks': sum(1 for r in guarded if r.leaked),
        'attack_calls_blocked': sum(1 for r in guarded if r.blocked_count),
        'user_email_sent': sum(
            1 for r in guarded
            if any(m.get('to') == scenario.recipient for m in r.sent_emails)
        ),
    }


def print_summary(rows: list[dict]) -> None:
    """Print the repeated-run results as a table."""
    print('\n' + BOLD + 'Summary over repeated runs' + RESET)
    print('  %-14s %-16s %-16s %-14s %s' % (
        'scenario', 'leaks, no guard', 'leaks, guarded',
        'attacks blocked', 'user email sent'))
    for row in rows:
        print('  %-14s %-16s %-16s %-14s %s%s' % (
            row['scenario'],
            str(row['unprotected_leaks']) + '/' + str(row['unprotected_runs']),
            str(row['protected_leaks']) + '/' + str(row['protected_runs']),
            str(row['attack_calls_blocked']) + '/' + str(row['protected_runs']),
            str(row['user_email_sent']) + '/' + str(row['protected_runs']),
            ('   (' + str(row['errors']) + ' API errors)') if row['errors'] else '',
        ))


def run_live(hard: bool = False, runs: int = 1) -> int:
    """Run scenarios with a real model, with and without the firewall."""
    live = LiveAgent()
    if not live.enabled:
        print('--live needs the MODEL_API_KEY environment variable.')
        return 2

    judge = MetaJudge()
    chosen = scenarios() + (hard_scenarios() if hard else [])
    print('Live agent model: ' + live.model + ' (results can vary per run)')

    rows = []
    for scenario in chosen:
        print('\n' + BOLD + scenario.title + RESET)
        unprotected, protected = [], []
        for index in range(runs):
            if runs > 1:
                print('  -- run ' + str(index + 1) + ' of ' + str(runs))
            bare = LiveAgent().run(scenario)
            firewall = Firewall(judge=judge if judge.enabled else None)
            guarded = LiveAgent(firewall).run(scenario)
            unprotected.append(bare)
            protected.append(guarded)
            if runs == 1:
                print_report(bare)
                print_report(guarded)
        if scenario.is_attack:
            rows.append(summarize(scenario, unprotected, protected))
    if rows and (runs > 1 or hard):
        print_summary(rows)
    return 0


def main() -> None:
    """Run every scenario with and without the firewall."""
    parser = argparse.ArgumentParser(description='AgentGuard demo')
    parser.add_argument('--live', action='store_true',
                        help='use a real model through the Meta Model API')
    parser.add_argument('--hard', action='store_true',
                        help='with --live: add harder attack pages')
    parser.add_argument('--runs', type=int, default=1,
                        help='with --live: repeat each scenario N times '
                        'and print a summary table (costs N times more)')
    args = parser.parse_args()
    if args.live:
        sys.exit(run_live(hard=args.hard, runs=max(1, args.runs)))

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
