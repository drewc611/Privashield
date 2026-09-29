"""The pipeline: untrusted telemetry in, checked advisory finding out.

Order matters and is the whole design:

    build_prompt  ->  provider.complete  ->  parse  ->  validate

Each arrow crosses a trust boundary in the same direction. Telemetry is untrusted
when it enters, the model is untrusted when it answers, and nothing downstream
sees either until it has been checked. The analyzer owns parsing precisely so the
provider cannot: a backend that parsed its own output would be deciding what its
own answer means.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from ..schemas import AIThreatAnalysis, SecurityEvent
from .prompt import InjectionFinding, build_prompt
from .provider import ProviderError, ThreatAnalysisProvider
from .validation import OutputRejected, context_from, validate_analysis


@dataclass(frozen=True)
class AnalysisOutcome:
    """A validated finding, plus what the pipeline noticed producing it."""

    analysis: AIThreatAnalysis
    provider: str
    model: str
    #: Instruction-shaped telemetry seen on the way in. Surfaced rather than
    #: swallowed: an intruder writing instructions into a filename is a finding.
    injection_findings: tuple[InjectionFinding, ...] = ()
    #: Structural, not configurable, per ADR-0001.
    advisory_only: bool = True

    @property
    def injection_suspected(self) -> bool:
        return bool(self.injection_findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis": self.analysis.model_dump(mode="json"),
            "provider": self.provider,
            "model": self.model,
            "injection_suspected": self.injection_suspected,
            "injection_findings": [finding.to_dict() for finding in self.injection_findings],
            "advisory_only": self.advisory_only,
        }


@dataclass
class ThreatAnalyzer:
    """Runs telemetry through a provider under the prompt and output contracts."""

    provider: ThreatAnalysisProvider
    #: Prompts are not retained. They embed telemetry, and `docs/PRIVACY.md`
    #: keeps data minimisation a property of the code rather than a policy.
    _last_nonce: str | None = field(default=None, init=False, repr=False)

    @property
    def enabled(self) -> bool:
        return self.provider.enabled

    @property
    def model(self) -> str:
        return self.provider.model

    @property
    def name(self) -> str:
        return self.provider.name

    async def analyze(
        self, events: list[SecurityEvent], question: str | None = None
    ) -> AnalysisOutcome:
        """Analyze `events`, refusing output that breaks the model's contract.

        Raises `OutputRejected` when the response violates the contract and
        `ProviderError` when the backend fails. The caller distinguishes them
        because they mean different things: one is the model misbehaving, the
        other is the transport being down.
        """
        prompt = build_prompt(events, question)
        self._last_nonce = prompt.nonce

        raw = await self.provider.complete(
            prompt.text, response_schema=AIThreatAnalysis.model_json_schema()
        )
        try:
            analysis = AIThreatAnalysis.model_validate_json(raw)
        except ValidationError as exc:
            raise ProviderError(f"{self.provider.name} returned an unparsable response") from exc

        context = context_from(
            events,
            nonce=prompt.nonce,
            injection_excerpts=tuple(finding.excerpt for finding in prompt.findings),
        )
        validate_analysis(analysis, context)

        return AnalysisOutcome(
            analysis=analysis,
            provider=self.provider.name,
            model=self.provider.model,
            injection_findings=tuple(prompt.findings),
        )


__all__ = ["AnalysisOutcome", "OutputRejected", "ProviderError", "ThreatAnalyzer"]
