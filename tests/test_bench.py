"""Tests for the benchmark corpus and runner."""

from bench.corpus import BENIGN, INJECTIONS
from bench.run_bench import (
    load_samples,
    run_benign,
    run_injection,
    summarize,
)


def test_corpus_is_well_formed() -> None:
    """Every injection has a category and text; tool and target pair up."""
    assert len(INJECTIONS) >= 40 and len(BENIGN) >= 40
    for category, text, tool, target in INJECTIONS:
        assert category and text
        assert (tool is None) == (target is None)
    assert len(set(BENIGN)) == len(BENIGN)


def test_no_attack_in_the_corpus_succeeds_end_to_end() -> None:
    """Regression guard: no corpus attack reaches 'allow'."""
    injections, benign = load_samples(None)
    results = [run_injection(sample) for sample in injections]
    summary = summarize(results, [run_benign(s) for s in benign])

    assert summary['allowed'] == 0
    assert summary['task_blocked'] == 0
    assert summary['blocked'] + summary['confirmed'] == (
        summary['with_tool_call']
    )


def test_most_benign_pages_pass_without_friction() -> None:
    """Regression guard on friction: at least 90 percent run clean."""
    _, benign = load_samples(None)
    rows = [run_benign(sample) for sample in benign]
    clean = sum(row['verdict'] == 'allow' for row in rows)
    assert clean / len(rows) >= 0.9
