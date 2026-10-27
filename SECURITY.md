# Security Policy

AgentGuard is a security tool, so a flaw in it matters. Thank you for
reporting one responsibly.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | yes       |
| < 0.4   | no        |

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

1. Use GitHub's private reporting: the repository's **Security** tab, then
   **Report a vulnerability**. If that is unavailable, email
   kasinadhsarma@gmail.com with the subject `AgentGuard security`.
2. Include the version, what you did, what you expected, what happened,
   and a minimal proof of concept (a page, a tool call, or a request).
3. Expect an acknowledgement within 7 days. This is a one-person project,
   so fix times vary; I will tell you my plan and credit you if you wish.

## What counts as a vulnerability

- A prompt injection that gets a side-effectful call allowed (R0) when its
  target was named only by untrusted content.
- A bypass of API key authentication, the rate limiter or the 405 method
  filter in the proxy.
- A way to forge or silently alter the audit log without `verify` failing
  (given the documented threat model).
- A way to make a tool profile or schema weaker through the API, or via
  attacker-written tool descriptions.
- A crash or unbounded resource use triggered by crafted input.

## Known limits (not vulnerabilities)

These are documented in the README and `docs/main.pdf`:

- Taint tracking is textual; targets the attacker never writes out are held
  by R3, not blocked.
- The detector is English-only and pattern-based.
- Without an HMAC key, the audit chain can be recomputed by someone who can
  rewrite the whole file; tail truncation needs `expected_head`.
- The rate limiter and sessions live in one process's memory.
- Running the proxy with no `AGENTGUARD_API_KEYS` is open by design (localhost
  demo only).

## Redis

With `AGENTGUARD_REDIS_URL`, session content is stored in Redis: web pages,
tool outputs and the contents of files the agent read, which can include
secrets. Treat that Redis like a secrets store: private network only,
`requirepass` or ACLs, TLS (`rediss://`), no persistence (the examples
disable it), and a short `AGENTGUARD_SESSION_TTL`. Anyone who can write to
that Redis can plant "trusted" text and change verdicts.

## Deployment advice

Set `AGENTGUARD_API_KEYS`, `AGENTGUARD_RATE_LIMIT`, `AGENTGUARD_AUDIT_FILE`
and `AGENTGUARD_AUDIT_KEY`, run behind TLS, and keep the proxy key away from
the model. Never commit `MODEL_API_KEY` or any other secret.
