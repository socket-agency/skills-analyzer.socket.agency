"""Runs the eval corpus and asserts clean separation across panel draws (§10)."""

from __future__ import annotations

from tests.eval.harness import evaluate, self_scan_clean


def test_corpus_precision_recall_stable_across_draws():
    for seed in range(3):
        metrics, failures = evaluate(seed)
        assert not failures, failures
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0


def test_self_scan_clean_via_harness():
    assert self_scan_clean() is True
