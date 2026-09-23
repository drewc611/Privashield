"""The adaptive detector: scoring, learning, and persistence.

Authority boundary, restated here because it is the constraint that shapes
everything else. `docs/AI_MODEL_GOVERNANCE.md` allows a model to classify,
summarize and propose. It does not allow a model to enforce. A score produced
here is advisory: it can raise an assessment for an analyst, and it can never
activate policy, alter firewall state, or move a response action out of the
approval-gated state machine. `AdaptiveAssessment.advisory_only` is fixed True
and asserted in tests so that stays a property of the code and not a promise in
a document.

State is persisted as plain JSON rather than a pickle. Pickle would execute
arbitrary code on load, which is an unacceptable property for a file a security
appliance reads at startup. JSON is also inspectable: an operator can open the
model and read its weights, which matters for a product whose case rests on
being auditable.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..feedback_models import AnalystFeedback, FeedbackLabel
from ..schemas import SecurityEvent
from .features import extract_features
from .guard import (
    TRAINABLE_LABELS,
    CanaryResult,
    GuardConfig,
    PoisoningGuard,
    RejectionReason,
    evaluate_canary,
)
from .online import OnlineLogisticRegression, OnlineMLP, model_from_state

STATE_VERSION = 1


@dataclass(frozen=True)
class AdaptiveAssessment:
    """What the detector believes about one event, and why."""

    score: float
    model_kind: str
    model_updates: int
    contributions: tuple[tuple[str, float], ...]
    #: Structural, not configurable. A learned score never carries authority.
    advisory_only: bool = True

    @property
    def confidence(self) -> float:
        """Distance from an undecided 0.5, scaled to [0, 1].

        An untrained model returns ~0.5 for everything, which should read as "no
        opinion" rather than "borderline malicious". Exposing this separately
        stops a fresh model's scores from being mistaken for judgements.
        """
        return abs(self.score - 0.5) * 2.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "confidence": self.confidence,
            "model_kind": self.model_kind,
            "model_updates": self.model_updates,
            "contributions": [
                {"feature": name, "contribution": value} for name, value in self.contributions
            ],
            "advisory_only": self.advisory_only,
        }


@dataclass(frozen=True)
class LearningOutcome:
    """The result of offering one piece of feedback to the detector."""

    applied: bool
    weight: float = 0.0
    loss: float | None = None
    reason: RejectionReason | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "applied": self.applied,
            "weight": self.weight,
            "loss": self.loss,
            "reason": self.reason.value if self.reason else None,
            "detail": self.detail,
        }


@dataclass
class AdaptiveDetector:
    """Scores events and learns from analyst feedback, under guard."""

    model: OnlineLogisticRegression | OnlineMLP = field(default_factory=OnlineLogisticRegression)
    guard: PoisoningGuard = field(default_factory=PoisoningGuard)
    #: Accuracy on the committed corpus at the last accepted state. Learning
    #: freezes if the model falls meaningfully below it.
    canary_baseline: float = 0.0
    #: Ground truth the detector re-checks itself against while it learns.
    #: Without this the rate limits are the only defense, and measurement shows
    #: they are not enough: against a 60-update model, 15 poisoned updates at a
    #: 20% influence cap already drop a 0.99 score to 0.27. Caps raise an
    #: attacker's cost; only the canary bounds the damage. Supply a corpus in
    #: any deployment where learning is enabled.
    canary_corpus: Sequence[tuple[SecurityEvent, float]] | None = None
    #: How often, in applied updates, to re-run the canary.
    canary_interval: int = 20
    #: Model state at the last verified-good canary. Freezing alone leaves the
    #: poisoned weights in place, which is the worst outcome available: a
    #: detector that is both blind and unteachable. Measured: with a 10-update
    #: canary cadence the poison that lands between checks is enough to push a
    #: 0.99 score to 0.32, so detection has to come with reversal.
    trusted_model_state: dict[str, Any] | None = field(default=None, repr=False)

    # -- scoring ----------------------------------------------------------

    def score(self, event: SecurityEvent) -> AdaptiveAssessment:
        features = extract_features(event)
        probability = self.model.predict(features)
        contributions: tuple[tuple[str, float], ...] = ()
        if isinstance(self.model, OnlineLogisticRegression):
            contributions = tuple(self.model.explain(features))
        return AdaptiveAssessment(
            score=probability,
            model_kind=self.model.kind,
            model_updates=self.model.updates,
            contributions=contributions,
        )

    # -- learning ---------------------------------------------------------

    def learn(
        self,
        event: SecurityEvent,
        feedback: AnalystFeedback,
        *,
        source: str,
        now: datetime | None = None,
    ) -> LearningOutcome:
        """Offer one labelled event to the model. The guard may refuse it."""
        decision = self.guard.evaluate(
            label=feedback.label,
            source=source,
            identity_verified=feedback.identity_verified,
            now=now,
        )
        if not decision.accepted:
            return LearningOutcome(applied=False, reason=decision.reason, detail=decision.detail)

        target = TRAINABLE_LABELS[feedback.label]
        features = extract_features(event)
        loss = self.model.update(features, target, decision.weight)
        self.guard.record(label=feedback.label, source=source, now=now)

        # Re-check ground truth on a cadence. A detector that has been taught to
        # ignore a known attack looks healthy from every other angle, so this
        # cannot wait for someone to run it by hand.
        if self.canary_corpus and self.model.updates % self.canary_interval == 0:
            self.run_canary(self.canary_corpus)

        return LearningOutcome(applied=True, weight=decision.weight, loss=loss)

    # -- canary -----------------------------------------------------------

    def run_canary(
        self,
        corpus: Sequence[tuple[SecurityEvent, float]],
        *,
        tolerance: float = 0.05,
        freeze_on_degradation: bool = True,
    ) -> CanaryResult:
        """Check the model against committed ground truth, freezing on decay."""
        predictions = [
            (self.model.predict(extract_features(event)), expected) for event, expected in corpus
        ]
        result = evaluate_canary(predictions, baseline=self.canary_baseline, tolerance=tolerance)
        if not result.degraded:
            # Checkpoint: this state is verified against ground truth, so it is
            # somewhere safe to return to.
            self.trusted_model_state = self.model.to_state()
            return result
        if freeze_on_degradation:
            restored = self.restore_trusted_state()
            detail = (
                "rolled back to last verified state"
                if restored
                else "no verified state to roll back to"
            )
            self.guard.freeze(
                f"canary degraded: {result.summary}; {detail}; learning halted pending review"
            )
        return result

    def restore_trusted_state(self) -> bool:
        """Return the model to its last canary-verified weights.

        Returns False when no verified state exists, which is itself worth
        reporting: it means learning ran without ever passing ground truth.
        """
        if self.trusted_model_state is None:
            return False
        self.model = model_from_state(self.trusted_model_state)
        return True

    def accept_canary_baseline(self, result: CanaryResult) -> None:
        """Adopt the current accuracy as the bar future learning must clear."""
        self.canary_baseline = result.accuracy
        self.trusted_model_state = self.model.to_state()

    # -- persistence ------------------------------------------------------

    def to_state(self) -> dict[str, Any]:
        return {
            "state_version": STATE_VERSION,
            "saved_at": datetime.now(UTC).isoformat(),
            "canary_baseline": self.canary_baseline,
            "trusted_model_state": self.trusted_model_state,
            "frozen_reason": self.guard.frozen_reason,
            "guard": {
                "verified_weight": self.guard.config.verified_weight,
                "unverified_weight": self.guard.config.unverified_weight,
                "window_seconds": self.guard.config.window.total_seconds(),
                "max_source_share": self.guard.config.max_source_share,
                "min_updates_before_capping": self.guard.config.min_updates_before_capping,
                "label_flood_threshold": self.guard.config.label_flood_threshold,
            },
            "model": self.model.to_state(),
        }

    def save(self, path: Path) -> None:
        """Write state atomically, so a crash mid-write cannot corrupt it."""
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(self.to_state(), indent=2, sort_keys=True), encoding="utf-8"
        )
        temporary.replace(path)

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> AdaptiveDetector:
        version = state.get("state_version")
        if version != STATE_VERSION:
            raise ValueError(
                f"unsupported adaptive detector state version: {version!r} "
                f"(this build reads {STATE_VERSION})"
            )
        guard_state = state.get("guard", {})
        config = GuardConfig(
            verified_weight=float(guard_state.get("verified_weight", 1.0)),
            unverified_weight=float(guard_state.get("unverified_weight", 0.0)),
            window=timedelta(seconds=float(guard_state.get("window_seconds", 86400.0))),
            max_source_share=float(guard_state.get("max_source_share", 0.35)),
            min_updates_before_capping=int(guard_state.get("min_updates_before_capping", 20)),
            label_flood_threshold=int(guard_state.get("label_flood_threshold", 50)),
        )
        guard = PoisoningGuard(config=config)
        frozen = state.get("frozen_reason")
        if frozen:
            guard.freeze(str(frozen))

        detector = cls(
            model=model_from_state(state["model"]),
            guard=guard,
            canary_baseline=float(state.get("canary_baseline", 0.0)),
            trusted_model_state=state.get("trusted_model_state"),
        )
        return detector

    @classmethod
    def load(cls, path: Path) -> AdaptiveDetector:
        return cls.from_state(json.loads(path.read_text(encoding="utf-8")))

    # -- observability ----------------------------------------------------

    def status(self) -> dict[str, Any]:
        """A snapshot suitable for an operator endpoint or health check."""
        top: list[dict[str, Any]] = []
        if isinstance(self.model, OnlineLogisticRegression):
            top = [
                {"feature": name, "weight": weight} for name, weight in self.model.top_features(10)
            ]
        return {
            "model_kind": self.model.kind,
            "updates": self.model.updates,
            "learning_frozen": self.guard.frozen,
            "frozen_reason": self.guard.frozen_reason,
            "canary_baseline": self.canary_baseline,
            "canary_enabled": bool(self.canary_corpus),
            "canary_interval": self.canary_interval,
            "has_trusted_state": self.trusted_model_state is not None,
            "window_sources": self.guard.window_stats(),
            "top_features": top,
            "advisory_only": True,
        }


def trainable_labels() -> tuple[FeedbackLabel, ...]:
    """Labels that carry a training signal, in declaration order."""
    return tuple(TRAINABLE_LABELS)


__all__ = [
    "STATE_VERSION",
    "AdaptiveAssessment",
    "AdaptiveDetector",
    "LearningOutcome",
    "trainable_labels",
]
