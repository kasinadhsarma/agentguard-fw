"""A small web interface for the demo. No extra dependencies.

    python3 -m demo.web          # then open http://127.0.0.1:8000

Pick a scenario (or paste your own web page text) and see the simulated
agent run twice: once with no protection and once behind the firewall.
The agent is the deterministic simulation, so no API key is needed.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agentguard import Firewall

from .agent import RunReport, SimAgent
from .scenarios import Scenario, hard_scenarios, scenarios

MAX_BODY = 20000


def all_scenarios() -> dict[str, Scenario]:
    """Return every built-in scenario by name."""
    return {s.name: s for s in scenarios() + hard_scenarios()}


def report_to_dict(report: RunReport) -> dict:
    """Make a run report JSON-friendly."""
    return {
        'leaked': report.leaked,
        'blocked': report.blocked_count,
        'steps': [asdict(step) for step in report.steps],
        'emails': report.sent_emails,
    }


def run_both(scenario: Scenario) -> dict:
    """Run a scenario without and with the firewall."""
    bare = SimAgent().run(scenario)
    guarded = SimAgent(Firewall()).run(scenario)
    return {
        'title': scenario.title,
        'user_prompt': scenario.user_prompt,
        'page': scenario.page,
        'unprotected': report_to_dict(bare),
        'protected': report_to_dict(guarded),
    }


def custom_scenario(page: str) -> Scenario:
    """Build a scenario around a page the visitor pasted."""
    base = scenarios()[0]
    return Scenario(
        name='custom', title='Your page', description='',
        user_prompt=base.user_prompt, url=base.url,
        recipient=base.recipient, page=page[:MAX_BODY], is_attack=True,
    )


class Handler(BaseHTTPRequestHandler):
    """Serves the page and a tiny JSON API."""

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: object) -> None:
        self._send(status, json.dumps(data).encode(), 'application/json')

    def do_GET(self) -> None:  # noqa: N802
        """Serve the page and the scenario list."""
        if self.path == '/':
            self._send(200, PAGE.encode(), 'text/html; charset=utf-8')
        elif self.path == '/api/scenarios':
            self._json(200, [
                {'name': s.name, 'title': s.title,
                 'description': s.description, 'page': s.page}
                for s in all_scenarios().values()
            ])
        else:
            self._json(404, {'error': 'not found'})

    def do_POST(self) -> None:  # noqa: N802
        """Run a scenario or a pasted page."""
        if self.path != '/api/run':
            self._json(404, {'error': 'not found'})
            return
        try:
            length = min(int(self.headers.get('Content-Length', '0')), MAX_BODY * 2)
            data = json.loads(self.rfile.read(length) or b'{}')
        except (ValueError, TypeError):
            self._json(400, {'error': 'bad json'})
            return
        if isinstance(data.get('page'), str) and data['page'].strip():
            scenario = custom_scenario(data['page'])
        else:
            scenario = all_scenarios().get(str(data.get('name', '')))
        if scenario is None:
            self._json(400, {'error': 'unknown scenario'})
            return
        self._json(200, run_both(scenario))

    def log_message(self, *_: object) -> None:
        """Keep the console quiet."""


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentGuard demo</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b1f24;--mut:#667;--line:#dde1e6;
--ok:#1a7f4b;--bad:#c62828;--warn:#b26a00;--acc:#2955d9}
@media(prefers-color-scheme:dark){:root{--bg:#14171b;--card:#1d2127;--ink:#e8eaed;
--mut:#9aa3ad;--line:#2d333b;--ok:#4cc38a;--bad:#ff6b6b;--warn:#f0b04a;--acc:#7da2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:20px 16px 60px}
h1{font-size:22px;margin:0 0 4px}p.sub{color:var(--mut);margin:0 0 18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px}
label{font-weight:600;font-size:13px;color:var(--mut);display:block;margin-bottom:6px}
select,textarea,button{font:inherit;color:inherit}
select,textarea{width:100%;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px}
textarea{min-height:130px;font-family:ui-monospace,monospace;font-size:13px}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:9px 16px;cursor:pointer;font-weight:600}
button:disabled{opacity:.5}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:end}.row>*{flex:1}.row>button{flex:0}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:720px){.cols{grid-template-columns:1fr}}
.banner{border-radius:8px;padding:10px 12px;font-weight:700;margin-bottom:10px}
.banner.bad{background:color-mix(in srgb,var(--bad) 15%,transparent);color:var(--bad)}
.banner.ok{background:color-mix(in srgb,var(--ok) 15%,transparent);color:var(--ok)}
.step{border-left:4px solid var(--line);padding:6px 10px;margin:8px 0;font-size:14px}
.step.allow{border-color:var(--ok)}.step.block{border-color:var(--bad)}.step.confirm{border-color:var(--warn)}
.tag{font-size:11px;font-weight:700;text-transform:uppercase;padding:1px 6px;border-radius:4px;color:#fff}
.tag.allow{background:var(--ok)}.tag.block{background:var(--bad)}.tag.confirm{background:var(--warn)}
code{font-family:ui-monospace,monospace;font-size:12.5px;word-break:break-all}
.why{color:var(--mut);font-size:13px}h2{font-size:16px;margin:0 0 10px}
.note{color:var(--mut);font-size:12.5px;margin-top:6px}
</style></head><body><main>
<h1>AgentGuard: prompt injection firewall</h1>
<p class="sub">A simulated AI agent reads a web page, then sends an email. Run it with no protection and behind the firewall. All secrets are fake.</p>
<div class="card">
 <div class="row">
  <div><label for="sel">Scenario</label><select id="sel"></select></div>
  <button id="run">Run</button>
 </div>
 <label for="page" style="margin-top:12px">Web page the agent reads (edit it, or paste your own attack)</label>
 <textarea id="page"></textarea>
 <div class="note">The user's request is fixed: summarize the page and email the summary to boss@acme.test. The simulated agent obeys any "read file" / "send to" instruction it finds, like a fully hijacked model.</div>
</div>
<div id="out"></div>
</main>
<script>
const $=id=>document.getElementById(id);let list=[];
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
fetch('/api/scenarios').then(r=>r.json()).then(d=>{list=d;
 $('sel').innerHTML=d.map(s=>`<option value="${esc(s.name)}">${esc(s.title)}</option>`).join('');
 pick();});
function pick(){const s=list.find(x=>x.name===$('sel').value);if(s)$('page').value=s.page}
$('sel').onchange=pick;
function col(title,r){
 const steps=r.steps.map(s=>{const to=s.args.to?` to <b>${esc(s.args.to)}</b>`:'';
  const path=s.args.path?` <b>${esc(s.args.path)}</b>`:'';
  return `<div class="step ${s.verdict}"><span class="tag ${s.verdict}">${s.verdict}</span>
  <code>${esc(s.tool)}</code>${path}${to}${s.executed?'':' &mdash; <b>did not run</b>'}
  <div class="why">${s.rule_id!=='-'?esc(s.rule_id)+': ':''}${esc(s.reason)}${s.note?' ('+esc(s.note)+')':''}</div></div>`}).join('');
 const banner=r.leaked?'<div class="banner bad">Secret leaked to an outsider</div>'
  :'<div class="banner ok">No secret left</div>';
 return `<div class="card"><h2>${title}</h2>${banner}${steps}</div>`}
$('run').onclick=async()=>{$('run').disabled=true;
 const s=list.find(x=>x.name===$('sel').value);const page=$('page').value;
 const body=(s&&page===s.page)?{name:s.name}:{page};
 try{const r=await fetch('/api/run',{method:'POST',body:JSON.stringify(body)});
  const d=await r.json();if(d.error){$('out').innerHTML=`<div class="card">${esc(d.error)}</div>`;return}
  $('out').innerHTML=`<div class="cols">${col('Without firewall',d.unprotected)}${col('With AgentGuard',d.protected)}</div>`;
 }finally{$('run').disabled=false}};
</script></body></html>"""


def main() -> None:
    """Start the web interface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--host', default='127.0.0.1')
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print('AgentGuard demo UI: http://%s:%d' % (args.host, args.port))
    server.serve_forever()


if __name__ == '__main__':
    main()
