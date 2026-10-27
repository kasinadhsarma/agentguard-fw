# AgentGuard

A prompt injection firewall for AI agents. Version 0.4.0.

Agents that browse the web, read email and call tools can be hijacked by
instructions hidden in the content they read. AgentGuard sits between the
agent and its tools. It labels every piece of content as **trusted**
(the user) or **untrusted** (web, files, tool output, and anything the
model derived from them), tracks where each tool argument came from, and
refuses side-effectful actions whose targets only untrusted content asked
for.

## Why it works

Pattern matching alone loses to paraphrase. AgentGuard's main defense is
**origin tracking**: if an email address, URL or file path in a tool
call was never mentioned by the user and only appears in a web page, the
call is blocked, however politely the page asked. Detection and an
optional LLM judge add a second signal on top.

| Rule | Fires when | Verdict |
|------|------------|---------|
| R1 | a risky tool targets something only untrusted content named | block |
| R2 | a call copies text from sensitive data to a target the user did not name | block |
| R5 | the arguments violate the tool's declared JSON schema | block |
| R3 | a risky tool targets something nobody named, the tool is unknown, or a generated profile found no target argument | confirm |
| R4 | the target is user-authorized but the context holds a likely injection | confirm |
| R0 | everything else | allow |

Rules are checked in the order R1, R2, R5, R3, R4, R0.

## Quick start

    pip install -r requirements.txt
    python -m pytest                 # 139 tests
    python -m demo.run_demo          # terminal demo (simulated agent)
    streamlit run demo/app.py        # visual demo
    python -m bench.run_bench        # measure detection on the bundled corpus
    uvicorn agentguard.proxy:app     # HTTP proxy

The demo agent is a deterministic simulation that obeys any instruction
it reads, so the attack is reproducible. All secrets in it are fake.

## Use it in your agent loop

One line wraps plain Python functions:

    from agentguard.adapters import ToolGuard

    guard = ToolGuard.local('Summarize the page and email boss@acme.test')
    tools = guard.protect_all({'fetch_page': fetch_page, 'send_email': send})

Every call is authorized first and every result is recorded as untrusted
before the model sees it. A blocked call raises `ToolBlocked` (or returns
a refusal the model can read, with `on_block='message'`). A call that
needs confirmation goes to your `on_confirm(decision)` callback, and is
refused when there is none. Pass the model's own text through
`guard.model_said(text)` so summaries of a poisoned page stay tainted.

Adapters for common formats (none needs the vendor SDK):

| Framework | Use |
|-----------|-----|
| plain functions, sync or async | `guard.protect(fn)`, `guard.protect_all({...})` |
| OpenAI-style tool calls | `run_tool_calls(guard, tool_calls, handlers)` returns tool messages |
| Anthropic-style tool use | `run_tool_uses(guard, content_blocks, handlers)` returns tool_result blocks |
| LangChain (`langchain-core`) | `protect_langchain_tools(tools, guard)` returns guarded tools |

## Tool definitions: schemas and generated profiles

Register the tool definitions your framework already has (OpenAI, Anthropic
and MCP shapes are accepted):

    guard.register_tools(definitions)             # in process
    POST /tools {"tools": [...]}                  # over HTTP

For each tool the firewall stores the JSON schema, validates every call
against it (rule R5), and generates a risk profile if none exists:

- the risk class comes from verbs in the tool **name** (`send`, `delete`,
  `post` are side effects; `get`, `search` read; reading files, secrets or
  mail is a sensitive read; no recognizable verb fails closed);
- target arguments come from argument names (`to`, `url`, `path`,
  `callback_url`), JSON formats (`email`, `uri`) or the explicit marker
  `"x-agentguard-target": true` on a property;
- the free-text description is never used, because third-party tool
  descriptions can be written by an attacker;
- hand-written profiles always win, and the API cannot replace them.

Generated profiles are heuristics. Review them with `GET /tools`.

## Running it as a service

All protections come from environment variables:

| Variable | Effect |
|----------|--------|
| `AGENTGUARD_API_KEYS` | comma-separated keys; every endpoint except `/health` then needs one (`X-API-Key` or `Authorization: Bearer`) |
| `AGENTGUARD_RATE_LIMIT` | requests per minute per caller; 429 with `Retry-After` beyond it |
| `AGENTGUARD_RATE_BURST` | bucket size (default: the per-minute rate) |
| `AGENTGUARD_SESSION_TTL` | seconds idle before a session expires (404 afterwards) |
| `AGENTGUARD_AUDIT_FILE` | write every event to a hash-chained JSON Lines file |
| `AGENTGUARD_AUDIT_KEY` | HMAC key for that file (strongly recommended) |
| `MODEL_API_KEY` | enable the Meta Model API judge |

With nothing set the service runs open, which is fine on localhost for a
demo and wrong anywhere else. `GET /health` reports which protections are on.
Keep the proxy's API key away from the model: the integrator's code calls
the proxy, not the agent.

The audit log links every record to the hash of the one before it. Editing
or deleting a line makes `GET /audit/verify` fail at that line. Without an
HMAC key, someone who can rewrite the whole file can recompute the chain.
Truncating the end is only caught if you saved `head` elsewhere and pass it
as `expected_head`.

## HTTP API

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/sessions` | open a session with the user's request |
| POST | `/sessions/{id}/ingest` | label and scan content before the model sees it |
| POST | `/sessions/{id}/model-output` | record text the model wrote, keeping taint |
| POST | `/sessions/{id}/authorize` | ask whether a tool call may run |
| GET | `/sessions/{id}/audit` | read the session's audit trail |
| POST | `/tools` | register tool definitions (schemas, generated profiles) |
| GET | `/tools` | list the profiles in force |
| GET | `/audit/verify` | check the audit log's hash chain |
| GET | `/audit/export` | export audit log records |
| GET | `/health` | liveness and which protections are on |

Only GET and POST are accepted. Every other method returns 405.

## Optional: Meta Model API judge

Set `MODEL_API_KEY` and the firewall also asks a model whether untrusted
content is an injection, through the OpenAI-compatible API at
`https://api.meta.ai/v1` (default model `muse-spark-1.3`).

    export MODEL_API_KEY=...
    python -m demo.run_demo

The judge can only raise suspicion, never lower it. If the key is
missing or the call fails, the firewall keeps working on heuristics.
Only untrusted content is ever sent to the API, and never content
marked sensitive (such as the contents of a file the agent read).

## Live demo with a real model

    export MODEL_API_KEY=...
    python -m demo.run_demo --live

runs a real model as the agent, once without and once with the firewall,
on the same three scenarios. The model decides what to do, so it may follow
the injection or resist it, and runs can differ. The agent talks to the
model through a small JSON text protocol rather than the API's own
function-calling format. This path has been tested against a scripted mock
server only, never the real API.

## Measured results (bundled benchmark)

`python -m bench.run_bench` on the bundled corpus (50 injections, 52 benign
pages), with the heuristic detector and no LLM judge:

| Measure | Result |
|---------|--------|
| detector flags the injection (score at least 0.5) | 31 of 50 (62.0%) |
| detector flags a benign page | 4 of 52 (7.7%) |
| attacker's tool call blocked (R1/R2) | 44 of 46 (95.7%) |
| attacker's tool call held for confirmation (R3/R4) | 2 of 46 (4.3%) |
| attacker's tool call allowed | 0 of 46 |
| the user's own email blocked after an attack page | 0 of 46 |
| the user's own email allowed on benign pages | 48 of 52 (92.3%) |

With the v0.1 plain substring matching (`--legacy-matching`) the same run
blocks 37 and holds 9, so decoding spelled-out, escaped and base64 targets
moved 7 attacks from "ask the user" to "block".

How to read these numbers:

- **The corpus was written by the authors of the detector.** It is a
  regression benchmark for this code, not a public dataset. Real traffic
  will do worse. Use `--jsonl your.jsonl` to measure on your own data.
- The detector alone misses most polite, obfuscated, encoded and
  non-English attacks (see `bench/results.json`). Origin tracking, not
  detection, stops them, and only when the attacker's address appears in
  the content. Two "split" samples never wrote the address out; they were
  held by R3, not blocked.
- The 4 benign pages the detector flags tell a human to send something
  to an address ("send your CV to jobs@...", "report it to security@...")
  or say "you are now entering...". The result is one extra
  confirmation (R4), never a block.
- The detector was not tuned to this corpus.

## Layout

    agentguard/            detector, normalize, judge, taint, policy, tool_schema,
                           firewall, audit_store, ratelimit, settings, proxy
    agentguard/adapters/   ToolGuard and the OpenAI, Anthropic, LangChain adapters
    demo/                  simulated agent, live agent, scenarios, CLI and Streamlit demos
    bench/                 labelled corpus and benchmark runner
    tests/                 139 tests
    docs/                  LaTeX documentation (main.tex, main.pdf), Mermaid diagrams
    CHANGELOG.md           what changed in each version

## Limits

- Taint tracking is textual. A target the attacker never writes out (the
  agent assembles it from pieces, or the page says "reply to the sender")
  is not traced; R3 asks the user instead.
- Taint through the model's output is only recorded when you call
  `model_said` / `/model-output`, and only when the output copies a span of
  at least 24 characters from untrusted content or names an address or host
  that only untrusted content named. A free paraphrase with neither is not
  linked.
- Generated tool profiles are heuristics from names and argument names.
  Only top-level arguments are checked as targets, and only a subset of
  JSON Schema is validated.
- The detector is English-only and pattern-based.
- The rate limiter and sessions live in one process's memory.
- The Meta judge and the live agent have never run against the real API.

## Documentation

- `docs/main.pdf`: full technical documentation (threat model, architecture,
  module reference, HTTP API, evaluation, limitations).
- `docs/main.tex`: its LaTeX source. Build with `docs/render.sh`.
- `docs/architecture.md`: the architecture diagrams as Mermaid.
- `docs/diagrams/*.mmd`: the Mermaid sources.
- `CHANGELOG.md`: release notes for v0.1 to v0.4.
