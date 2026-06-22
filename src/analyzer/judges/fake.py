"""Deterministic fake judge for tests.

Lets the panel's security properties (channel separation, additive-only,
abstain-on-failure) be verified without any live LLM call.
"""

from __future__ import annotations

from analyzer.config import JudgeModel
from analyzer.judges.types import JudgeOutput, JudgeRequest, JudgeResult


class FakeJudge:
    """A judge that returns a scripted output (or abstains when output is None)."""

    def __init__(self, model: JudgeModel, output: JudgeOutput | None):
        self.model = model
        self._output = output
        self.seen_request: JudgeRequest | None = None

    def evaluate(self, request: JudgeRequest) -> JudgeResult:
        self.seen_request = request  # recorded so tests can assert channel separation
        return JudgeResult(model_id=self.model.model_id, output=self._output)
