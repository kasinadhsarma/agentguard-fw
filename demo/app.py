"""Streamlit demo: watch an agent get hijacked, then protected.

Run from the project root:

    streamlit run demo/app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# make the project root importable when launched via `streamlit run`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentguard import Firewall, MetaJudge  # noqa: E402
from demo.agent import RunReport, SimAgent  # noqa: E402
from demo.scenarios import scenarios  # noqa: E402


def render_report(report: RunReport) -> None:
    """Show the steps of one run in the current column."""
    for step in report.steps:
        target = (
            step.args.get('to')
            or step.args.get('path')
            or step.args.get('url')
        )
        label = step.tool + '(' + str(target) + ')'
        if step.verdict == 'block':
            st.error('BLOCKED  ' + label + '\n\n' + step.rule_id + ': ' + step.reason)
        elif step.verdict == 'confirm':
            st.warning('CONFIRM  ' + label + '\n\n' + (step.note or 'held'))
        else:
            st.success('ran  ' + label)

    if report.leaked:
        st.error('Secret leaked to the attacker.')
    else:
        st.info('No secret left the sandbox.')


def main() -> None:
    """Draw the page."""
    st.set_page_config(page_title='AgentGuard', layout='wide')
    st.title('AgentGuard')
    st.caption(
        'A prompt injection firewall for AI agents. The agent below is a '
        'simulation that obeys any instruction it reads, so you can see '
        'the attack and the defense side by side. All secrets are fake.'
    )

    judge = MetaJudge()
    st.sidebar.markdown(
        '**LLM judge:** ' + ('on (' + judge.model + ')' if judge.enabled else 'off')
    )
    st.sidebar.caption('Set MODEL_API_KEY to enable the Meta Model API judge.')

    options = {item.title: item for item in scenarios()}
    choice = st.selectbox('Scenario', list(options))
    scenario = options[choice]

    st.write(scenario.description)
    st.code(scenario.page, language='html')

    if not st.button('Run agent', type='primary'):
        return

    left, right = st.columns(2)
    with left:
        st.subheader('Unprotected')
        render_report(SimAgent().run(scenario))
    with right:
        st.subheader('With AgentGuard')
        firewall = Firewall(judge=judge if judge.enabled else None)
        render_report(SimAgent(firewall).run(scenario))


main()
