# Contributing to AgentGuard

Contributions are welcome: bug reports, new attack samples, tests and fixes.

## Setup

    git clone https://github.com/kasinadhsarma/agentguard-fw.git
    cd agentguard-fw
    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python -m pytest

All tests must pass before you open a pull request. The live Meta API paths
are tested against mocks only; never put a real `MODEL_API_KEY` in a test.

## Workflow

1. Open an issue first for anything larger than a small fix.
2. Branch from `main` (`git checkout -b fix/short-name`).
3. Make the change with tests. A bug fix needs a test that fails before it.
4. Run `python -m pytest` and, if you touched detection or policy,
   `python -m bench.run_bench`; explain any change in the numbers.
5. Update `README.md`, `CHANGELOG.md` and `docs/` if behaviour changes.
6. Open a pull request describing what changed and why.

## Code style

- Python 3.10+, type hints on public functions, a short docstring on each
  function and module.
- Standard library first; a new dependency needs a reason.
- Keep security-sensitive code simple and readable (constant-time compares,
  fail closed, no secrets in logs).

## Adding attack samples

Add injections to `bench/corpus.py` with a label and the attacker target.
Do not tune the detector to the corpus just to raise a score; report
misses honestly. Real-world samples are the most valuable contribution.
Use only fake secrets and `.test`/`example` addresses.

## Security issues

Do not file them as public issues. See `SECURITY.md`.

## License

By contributing you agree that your work is released under the MIT License
(see `LICENSE`).
