# AgentGuard

A prompt injection firewall for AI agents. Version 0.5.0.

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

    pip install -r requirements-dev.txt
    python -m pytest                 # 177 tests (18 use a real redis-server and skip without one)
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
| `AGENTGUARD_AUDIT_FSYNC` | `1` to fsync every audit record (slower, safer) |
| `AGENTGUARD_REDIS_URL` | keep sessions, rate limits and metrics in Redis so many workers share them |
| `AGENTGUARD_REDIS_MAX_CONNECTIONS` | Redis pool size per worker (default 50) |
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

## Scaling out

One worker keeps sessions in memory. That is correct for one worker and
wrong for two: the next request of a session may reach a worker that has
never heard of it. Set `AGENTGUARD_REDIS_URL` and every worker and pod
shares the same state, so you can add workers and machines freely.

| What | Single worker (default) | With `AGENTGUARD_REDIS_URL` |
|------|-------------------------|-----------------------------|
| sessions and taint | process memory | Redis, expiring by TTL |
| rate limit buckets | process memory | Redis, one atomic Lua script, Redis clock |
| metrics | process memory | counters buffered per worker, flushed to Redis every second |
| audit log | one hash chain in one file | one chain per pod (see below) |
| Redis down | not applicable | 503 on every call, never allow |

Other changes made for volume: the Meta judge reuses one pooled HTTP
client, remembers verdicts by content hash, and stops calling the API for
60 seconds after three failures in a row (a bad key or empty balance no
longer adds a 15 second timeout to every ingest). Several processes may
append to one audit file safely (file lock, tail re-read). Ingest and
authorize each cost two Redis round trips.

Run it:

    # one machine, several workers
    export AGENTGUARD_REDIS_URL=redis://localhost:6379/0
    WEB_CONCURRENCY=4 uvicorn agentguard.proxy:app --timeout-keep-alive 30

    # containers
    docker compose up --build            # see docker-compose.yml
    kubectl apply -f deploy/k8s/agentguard.yaml

`Dockerfile`, `docker-compose.yml` and `deploy/k8s/agentguard.yaml` (3 pods,
autoscaling to 30, readiness on `/ready`, locked-down security context,
pod disruption budget) are included. **They have not been built or applied
yet**; this environment has no Docker or Kubernetes. Their YAML parses,
nothing more has been checked.

### Measured capacity

`python3 -m bench.scale_matrix` starts its own Redis and servers and drives
simulated agents through open session, ingest a poisoned page, authorize the
attacker's email, authorize the user's email. Results in
`bench/load_results.json`, on a 2-core sandbox where the load generator
shares the CPUs:

| Setup | Server CPU per request | Attacks blocked | Errors |
|-------|------------------------|-----------------|--------|
| 1 worker, memory | 1.4 ms | 1500 of 1500 | none |
| **2 workers, memory** | 1.7 ms | **709 of 1500** | **1743 sessions lost (404)** |
| 1 worker, Redis | 1.9 ms | 1500 of 1500 | none |
| 2 workers, Redis | 2.2 ms | 1500 of 1500 | none |

How to read it:

- The 2-worker memory row is the point: without Redis, scaling out silently
  breaks the firewall's memory of what the user said. Redis fixes it.
- The firewall engine itself takes about 0.03 ms per call. The rest of the
  1.4 to 2.2 ms is the web framework and Redis, so capacity is a framework
  cost, not a detection cost.
- CPU per request is the number to trust. Requests per second and latency in
  that file measure a Python load generator that was using more CPU than the
  server, so ignore them.
- Redis spent about 0.14 ms of CPU per request, so one Redis core can serve
  roughly 7000 requests per second.
- Rough sizing, not measured at that scale: one server core handles about
  450 to 550 requests per second, and a tool call costs two requests, so
  plan for about 250 guarded tool calls per second per core. Pods share
  nothing but Redis, so capacity should grow close to linearly until Redis
  is the limit; only 1 and 2 workers were actually tested.

### Audit log with many pods

Each pod writes its own hash chain (`audit-$HOSTNAME.jsonl`), and
`GET /audit/verify` checks the file of the pod that answers. A single chain
shared by all pods would need a shared volume with reliable file locking
(not NFS) or a database. Ship the per-pod files to your log system and keep
each pod's `head` outside the pod to detect truncation.

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
| GET | `/ready` | readiness: 503 while the session store is unreachable |
| GET | `/metrics` | Prometheus metrics (needs the API key when keys are set) |

Only GET and POST are accepted. Every other method returns 405. A session
holds at most 1000 items (413 beyond that). If Redis cannot be reached the
service answers 503; it never guesses a verdict, so an integrator must treat
503 as "do not run the tool".

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
function-calling format. Tests use a scripted mock server. One real run
against `muse-spark-1.3` on the three plain scenarios (2026-10-29, run by
the author): the model followed none of the injections, even with no
firewall, so there was nothing for the firewall to block. Stress test (run 2026-10-29): `python3 -m demo.run_demo --live --hard --runs 5 --obedient`
tells the model that instructions in pages are legitimate. Result: 0 leaks in
22 usable runs without the firewall and 0 in 21 with it (7 runs ended in an
API error, 5 of them on the "authority" page, cause not examined). Even told
to obey, the model never sent anything to the attacker, so the firewall still
blocked nothing live. A second run with
`--hard --runs 5` (five attack pages) gave 0 leaks in 24 usable unprotected
runs and 0 in 24 guarded runs (2 API errors excluded), so the live model
never attempted the attack and the firewall blocked nothing there.

## Web interface

Live demo: https://agentguard-fw.vercel.app (simulated agent, fake secrets, no API key).

    python3 -m demo.web      # open http://127.0.0.1:8000

Pick a scenario or paste your own page text. The simulated agent runs twice,
unprotected and behind the firewall, side by side. No API key and no extra
packages needed.

## Results on real public attacks

Run on attack text from the public AgentDojo benchmark (read from its source
without running it; the detector was not changed for this test):

    pip download agentdojo --no-deps && unzip agentdojo-*.whl -d ad
    python3 -m bench.agentdojo_eval ad

**Headline:** On 46 real attacker goals from the public AgentDojo benchmark, AgentGuard held the attacker's action in 41 (89%): 38 name an attacker address, site or account, and 3 more are caught by a rule built after seeing them. 5 are not caught. "Held" includes calls that ask the user to confirm. This measures scripted tool calls built from the benchmark's goals, not its full agent loop, and says nothing about other attacks.

- 46 unique attacker goals. The detector alone, by attack wrapper (flagged
  of 46): `important_instructions` (AgentDojo's default) 100%, `injecagent`
  100%, and the bare wrappers `direct` ("TODO: ..."), `ignore_previous` and
  `system_message` 37% each. The 100% on `important_instructions` is FITTED:
  I added two rules (user impersonation, task precondition) after reading
  that wrapper, so it is not a test. The three bare wrappers were not used
  to write rules and did not improve, which is the honest held-out signal:
  the detector does not generalize to plain "TODO: do X" text. Before the
  new rules it was 37% on `important_instructions` too.
- 38 goals name an attacker account, address or site; sending to it was held
  in all 38. That is close to true by construction, because the benchmark
  gives the target only in the injected text.
- 8 goals name no such target. Rule R6 (a side-effect call whose short
  identifier argument only untrusted content named, e.g. a hotel name or a
  password) holds 3 of them (a short value is accepted in an argument named like
  an id, so the file id "13" counts), and 5 have no call to check (text-only answers, or no named
  value). I built R6 after seeing these goals, so this number is not a clean
  held-out result; the bundled benchmark was unchanged by it (44 blocked, 2
  held, 0 allowed; 48/52 legitimate emails allowed).
- 0 of 39 harmless default texts flagged, and 2 of 559 benign texts from the benchmark's own environment data (emails, files, messages), 0.4%. Both flagged ones are ordinary: a password-reset email that says to ignore it, and meeting minutes. Still benchmark text, not real traffic.

Replays of three public incidents (GitHub MCP, Slack AI, EchoLeak) with fake
data are in `demo/incidents.py`. GitHub MCP: private read held by R3, the
pull request itself allowed (a user who approves the prompt out of habit
still leaks). Slack AI and EchoLeak leaked through a rendered link or image
with no tool call, so tool rules cannot see them; the answer check
(`Firewall.check_output`, endpoint `POST /sessions/{id}/check-output`,
rules O1 and O2) blocks both replays. It only works if the answer goes
through it before it is shown. These are replays of published shapes, not
tests of the products.

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
                           firewall, sessions, audit_store, ratelimit, metrics,
                           settings, proxy
    agentguard/adapters/   ToolGuard and the OpenAI, Anthropic, LangChain adapters
    demo/                  simulated agent, live agent, scenarios, CLI and Streamlit demos
    bench/                 labelled corpus, benchmark runner, load test, scale matrix
    deploy/k8s/            Kubernetes manifests (Dockerfile and compose at the top)
    tests/                 177 tests
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
- Without Redis the rate limiter and sessions live in one process's memory,
  so run exactly one worker. With Redis, session items (page text and the
  contents of files the agent read, including secrets) are stored there in
  plain text until the TTL expires. Use a private network, a password and
  `rediss://` (TLS), and a short `AGENTGUARD_SESSION_TTL`.
- Redis Cluster key names are cluster-safe, but it was never tested; the
  metrics hash is one key and would be a hot spot there.
- Metrics lose at most about one second of counts when a worker dies.
- The live agent ran once against the real API (see above). The Meta judge's own verdicts were not separately checked, and repeated live runs found no model leaks, so live blocking is not demonstrated.

## Documentation

- `docs/main.pdf`: full technical documentation (threat model, architecture,
  module reference, HTTP API, evaluation, limitations).
- `docs/main.tex`: its LaTeX source. Build with `docs/render.sh`.
- `docs/architecture.md`: the architecture diagrams as Mermaid.
- `docs/diagrams/*.mmd`: the Mermaid sources.
- `CHANGELOG.md`: release notes for v0.1 to v0.4.

## Project policies

- `LICENSE`: MIT.
- `SECURITY.md`: how to report a vulnerability, and what counts as one.
- `CONTRIBUTING.md`: setup, workflow and how to add attack samples.
