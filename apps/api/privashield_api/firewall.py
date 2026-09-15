from __future__ import annotations

from .schemas import FirewallConfig, FirewallEvaluation, FirewallEvaluationRequest


class FirewallController:
    def __init__(self, mode: str = "observe", threshold: float = 0.85) -> None:
        self._config = FirewallConfig(mode=mode, threshold=threshold)

    @property
    def config(self) -> FirewallConfig:
        return self._config.model_copy()

    def update(self, config: FirewallConfig) -> FirewallConfig:
        self._config = config
        return self.config

    def evaluate(self, request: FirewallEvaluationRequest) -> FirewallEvaluation:
        decision = "would_drop" if request.risk_score >= self._config.threshold else "would_allow"
        return FirewallEvaluation(
            decision=decision,
            threshold=self._config.threshold,
            risk_score=request.risk_score,
            mode=self._config.mode,
            enforced=False,
            reason=request.reason,
        )
