"""Live LLM judge via LiteLLM (§4.7).

Only used when ``JUDGE_LIVE=1`` and provider keys are present. Capability-reduced:
the judge has no tools, no file access, no network beyond this one chat call — a
successful injection can at worst produce a wrong classification, never an action.
On any error or unparseable output (after one repair retry) the judge ABSTAINS.
"""

from __future__ import annotations

from analyzer.config import AnalyzerConfig, JudgeModel
from analyzer.judges.panel import parse_judge_output
from analyzer.judges.types import JudgeRequest, JudgeResult

_REPAIR = (
    "Your previous response was not valid JSON for the required schema. "
    'Respond with ONLY {"findings": [...]} and nothing else.'
)


class LiteLLMJudge:
    def __init__(self, model: JudgeModel, config: AnalyzerConfig):
        self.model = model
        self.config = config

    def evaluate(self, request: JudgeRequest) -> JudgeResult:
        try:
            import litellm
        except ImportError:
            return JudgeResult(self.model.model_id, None)

        messages = [
            {"role": "system", "content": request.system},
            {"role": "user", "content": request.data_block},
        ]
        try:
            raw = self._complete(litellm, messages)
            output = parse_judge_output(raw)
            if output is None:
                messages.append({"role": "user", "content": _REPAIR})
                output = parse_judge_output(self._complete(litellm, messages))
            return JudgeResult(self.model.model_id, output)
        except Exception:  # noqa: BLE001 — any provider/parse failure => abstain, never false-clean
            return JudgeResult(self.model.model_id, None)

    def _complete(self, litellm: object, messages: list[dict[str, str]]) -> str:
        resp = litellm.completion(  # type: ignore[attr-defined]
            model=self.model.model_id,
            messages=messages,
            response_format={"type": "json_object"},
            temperature=0,
            # Bound each call so a slow provider abstains (raises Timeout -> caught) rather
            # than hanging the panel; no internal retries multiplying that latency.
            timeout=self.config.judge_timeout_seconds,
            num_retries=0,
        )
        return resp.choices[0].message.content or ""
