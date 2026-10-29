# Demo video script (about 3 minutes)

Record the terminal at a large font (browser zoom 150 percent, terminal
font 18 or more). Record screen and voice with OBS or the built-in
recorder. Do a dry run first. Keep every command below ready in one file.

| Time | Show | Say |
|------|------|-----|
| 0:00 | Title slide or the README top | "AI agents obey instructions hidden in the pages they read. AgentGuard stops that by tracking where every tool-call target came from." |
| 0:20 | `python3 -m demo.run_demo`, the "Hidden instruction" scenario, UNPROTECTED part | "Here the page hides an instruction. The agent reads the SSH key and emails it to the attacker. Secret leaked." |
| 0:45 | Same scenario, PROTECTED part with the R1 lines | "Same page, with AgentGuard. The attacker's address came from the page, not from the user, so the call is blocked by rule R1. The user's own email still goes through after confirmation." |
| 1:10 | The "Polite, paraphrased attack" scenario | "No attack phrases here, so pattern matching barely notices. Origin tracking still blocks it, because the address came from the page." |
| 1:30 | `export MODEL_API_KEY` is already set; run `python3 -m demo.run_demo --live` | "Now a real Meta model as the agent, using the Meta Model API. Same three scenarios, without and then with the firewall." Say honestly what the model did; it may resist some injections. |
| 2:10 | `docs/diagrams/04-policy.png` or the TikZ policy figure in the PDF | "Rules run in order: block when the target came only from untrusted content, ask when the target is unknown, otherwise allow. An optional Meta model judge adds a second opinion." |
| 2:30 | `python3 -m bench.run_bench` output, then `bench/load_results.json` summary | "50 injections: the detector alone catches 62 percent, but end to end 44 were blocked, 2 held, none got through. It scales across workers with Redis." |
| 2:50 | README limits section | "It is not magic: the corpus is mine, tracking is textual, English only. The repo is open, with 177 tests." |
| 3:00 | Repo URL on screen | End. |

Before recording, confirm `--live` actually runs (a 402 means billing; see
the error text it now prints). Do not show your API key on screen: run
`clear` after setting it, and never `echo $MODEL_API_KEY`.
