"""Live LLM judge via LiteLLM (§4.7).

Only used when ``JUDGE_LIVE=1`` and provider keys are present. Capability-reduced:
the judge has no tools, no file access, no network beyond this one chat call — a
successful injection can at worst produce a wrong classification, never an action.
On any error or unparseable output (after one repair retry) the judge ABSTAINS.
"""

from __future__ import annotations

import logging

from analyzer.config import AnalyzerConfig, JudgeModel
from analyzer.judges.panel import parse_judge_output
from analyzer.judges.types import JudgeRequest, JudgeResult

# A judge abstains on failure (additive-only safety), but the abstention must not be
# silent — emit a log so an operator can see *which* judge failed and why. The app
# configures the handler; the library only emits (never logs artifact content/secrets).
logger = logging.getLogger("analyzer.judges")

_REPAIR = (
    "Your previous response was not valid JSON for the required schema. "
    'Respond with ONLY {"findings": [...]} and nothing else.'
)


class LiteLLMJudge:
    def __init__(self, model: JudgeModel, config: AnalyzerConfig):
        self.model = model
        self.config = config

    def evaluate(self, request: JudgeRequest) -> JudgeResult:
        model = self.model.model_id
        try:
            import litellm
        except ImportError:
            logger.warning("judge %s abstained: litellm is not installed", model)
            return JudgeResult(model, None)
        # Keep LiteLLM's "Provider List"/feedback banners (printed during internal cost
        # logging on the response) out of our logs — they're noise, not failures.
        litellm.suppress_debug_info = True

        messages = [
            {"role": "system", "content": request.system},
            {"role": "user", "content": request.data_block},
        ]
        try:
            output = parse_judge_output(self._complete(litellm, messages))
            if output is None:
                messages.append({"role": "user", "content": _REPAIR})
                raw = self._complete(litellm, messages)
                output = parse_judge_output(raw)
                if output is None:
                    # Log a short STRUCTURAL prefix (fence/brace), not the body — enough to
                    # see *why* it won't parse without dumping artifact-derived content.
                    logger.warning(
                        "judge %s abstained: no usable findings after repair retry (starts %r)",
                        model,
                        raw.lstrip()[:32],
                    )
            return JudgeResult(model, output)
        except Exception as exc:  # noqa: BLE001 — any provider/parse failure => abstain, never false-clean
            # str(exc) carries the provider error (no secrets); truncate to keep logs tidy.
            logger.warning("judge %s failed: %s: %s", model, type(exc).__name__, str(exc)[:300])
            return JudgeResult(model, None)

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
