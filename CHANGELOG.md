# Changelog

## 0.5.0

Scale out.

- `sessions.py`: sessions can live in Redis (`RedisSessionStore`) so any
  number of workers and pods share them. Append-only layout, no locks, two
  round trips for ingest and authorize, TTL by Redis, per-session item
  limit (413), 503 when Redis is unreachable (fail closed).
- `RedisRateLimiter`: one atomic Lua token bucket on the Redis clock.
- `metrics.py` and `GET /metrics`: Prometheus counters and a latency
  histogram by route template; buffered per worker, flushed to Redis every
  second and on shutdown. `GET /ready` readiness probe.
- Audit log: several processes can append to one file (flock plus tail
  re-read); `$VARS` in `AGENTGUARD_AUDIT_FILE` give each pod its own chain.
- Judge: pooled HTTP client, verdict cache by content hash, circuit
  breaker (a broken key no longer costs a timeout per ingest).
- Proxy: plain ASGI middleware (about 0.4 ms less CPU per request).
  Version 0.5.0.
- `Dockerfile`, `docker-compose.yml`, `deploy/k8s/agentguard.yaml`
  (not built or applied yet), `bench/load_test.py`,
  `bench/scale_matrix.py`, `bench/load_results.json`.
- Removed the unused per-session decision list (decisions are audit
  events). 37 new tests, 176 in total.

## 0.4.0

Adapters and a live demo.

- `agentguard.adapters`: `ToolGuard` wraps plain functions (sync and
  async) in one line; adapters for OpenAI-style tool calls,
  Anthropic-style tool use blocks and LangChain tools
  (`protect_langchain_tools`, tested against real `langchain-core`).
- Results of tools profiled as sensitive reads are marked sensitive
  automatically, so they cannot be copied out (R2) or sent to the judge.
- `demo/live_agent.py` and `python -m demo.run_demo --live`: a real model
  through the Meta Model API acts as the agent, with and without the
  firewall. Tested with a scripted mock server only.
- A generated side-effect profile that found no target argument now
  needs confirmation (R3) instead of running unchecked.

## 0.3.0

Production hardening and tool schemas.

- Proxy: API key authentication (401), per-caller token-bucket rate
  limit (429 with `Retry-After`, failed logins count too), idle session
  expiry, all configured from environment variables (`settings.py`).
- Tamper-evident audit log (`audit_store.py`): hash-chained JSON Lines,
  optional HMAC, `verify()`, `export()`, `GET /audit/verify`,
  `GET /audit/export`.
- Tool definitions (`tool_schema.py`): OpenAI, Anthropic and MCP shapes;
  generated risk profiles from names and argument names; JSON Schema
  validation of every call (new rule R5, block). Descriptions are never
  used. `POST /tools`, `GET /tools`.

## 0.2.0

Closing the known gaps.

- `normalize.py`: target matching now sees through spelled-out symbols
  (`[at]`, `dot`), percent and HTML escapes, spaces, zero-width
  characters and base64 blobs. Copied-secret detection sees base64 too.
- Taint through model output: `Firewall.record_model_output` and
  `POST /sessions/{id}/model-output`. Text derived from untrusted content
  stays untrusted, inherits its score and its sensitive flag.
- `bench/`: a hand-written labelled corpus (50 injections, 52 benign
  pages) and a runner that reports detector and end-to-end results. The
  corpus was written by the detector's authors, so it is a regression
  benchmark, not a public dataset.

## 0.1.0

First release: detector, taint tracker, policy rules R0 to R4, FastAPI
proxy (GET and POST only), optional Meta Model API judge, simulated
agent demo, 37 tests, LaTeX documentation.
