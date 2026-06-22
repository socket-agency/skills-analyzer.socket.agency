"""Shared types for the LLM judge layer.

The judge's only degree of freedom is filling :class:`JudgeOutput` — a strict
findings schema. It cannot emit free-form text or a verdict override.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict

from analyzer.models import Category, Confidence, Severity


class JudgeFinding(BaseModel):
    """One finding a judge may raise, in the canonical finding schema."""

    category: Category
    severity: Severity
    confidence: Confidence
    evidence: str
    risk: str
    remediation: str
    language: str | None = None
    file: str | None = None
    line: int | None = None


class JudgeOutput(BaseModel):
    """The forced structured output — the judge's ONLY degree of freedom.

    Strict: ``findings`` is required and extra keys are forbidden, so a malformed
    or off-schema response fails validation and the judge abstains (never clean).
    """

    model_config = ConfigDict(extra="forbid")

    findings: list[JudgeFinding]


@dataclass
class JudgeRequest:
    """A materialized, hardened prompt shared by every judge in a panel."""

    system: str
    data_block: str
    nonce: str


@dataclass
class JudgeResult:
    model_id: str
    output: JudgeOutput | None  # None => abstained (parse failure / error)

    @property
    def abstained(self) -> bool:
        return self.output is None
