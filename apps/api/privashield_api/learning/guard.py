"""Defenses for a detector that learns from analyst feedback.

A model that updates itself from labels is a model an attacker can teach. The
canonical attack is patient rather than clever: generate traffic that resembles
your intended intrusion, get it labelled benign often enough, and the detector
learns to ignore the thing you are about to do. Nothing about the model
architecture prevents this. The controls have to sit on the learning path.

Four are implemented here, in increasing order of how much they cost an
attacker:

1. Trust weighting. Feedback already records `identity_verified`. Labels from an
   unverified principal carry reduced weight, and can be refused outright.

2. Influence capping. No single source may supply more than a configured share
   of the updates in a window, so a flood of labels from one account cannot
   dominate the boundary however patient it is.

3. Label-flood detection. A burst of same-label feedback from one source in a
   short window is the signature of automated poisoning rather than of an
   analyst working a queue.

4. Canary evaluation. The committed detection corpus is immutable ground truth
   under version control. If learning degrades the model's agreement with it
   past a threshold, training freezes and the freeze is surfaced. This is the
   control that matters most: the first three raise the cost of an attack, this
   one bounds the damage when the cost is paid anyway.

None of this makes the learning path safe against an attacker who can already
forge verified analyst identities. At that point the audit ledger, not the
detector, is the control that matters.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from ..feedback_models import FeedbackLabel

# Labels that carry a usable training signal. NEEDS_REVIEW is deliberately
# excluded: it means the analyst has not decided, and treating indecision as a
# label is how a model learns noise.
TRAINABLE_LABELS: Mapping[FeedbackLabel, float] = {
    FeedbackLabel.TRUE_POSITIVE: 1.0,
    FeedbackLabel.FALSE_POSITIVE: 0.0,
    FeedbackLabel.BENIGN: 0.0,
}


class RejectionReason(StrEnum):
    """Why a piece of feedback was not allowed to train the model."""

    NOT_TRAINABLE = "not_trainable"
    UNVERIFIED_IDENTITY = "unverified_identity"
    INFLUENCE_CAP = "influence_cap"
    LABEL_FLOOD = "label_flood"
    TRAINING_FROZEN = "training_frozen"


@dataclass(frozen=True)
class GuardDecision:
    """The guard's verdict on one piece of feedback."""

    accepted: bool
    weight: float = 0.0
    reason: RejectionReason | None = None
    detail: str | None = None


@dataclass
class GuardConfig:
    """Tunable bounds for the learning path.

    Defaults are deliberately conservative. Loosening them trades resistance to
    a patient attacker for faster adaptation, which is a decision an operator
    should make knowingly rather than inherit.
    """

    #: Weight applied to feedback from a principal whose credential was verified.
    verified_weight: float = 1.0
    #: Weight applied when the credential was not verified. Zero refuses it.
    unverified_weight: float = 0.0
    #: Window over which influence and flood limits are measured.
    window: timedelta = timedelta(hours=24)
    #: Maximum share of updates in the window that one source may supply.
    max_source_share: float = 0.35
    #: Below this many updates in the window, the share cap is not enforced —
    #: otherwise the very first analyst to give feedback trips it immediately.
    min_updates_before_capping: int = 20
    #: Identical-label updates from one source within the window that count as
    #: a flood rather than ordinary queue work.
    label_flood_threshold: int = 50

    def __post_init__(self) -> None:
        if not 0.0 <= self.unverified_weight <= self.verified_weight:
            raise ValueError("unverified_weight must be between 0 and verified_weight")
        if not 0.0 < self.max_source_share <= 1.0:
            raise ValueError("max_source_share must be in (0, 1]")
        if self.window <= timedelta(0):
            raise ValueError("window must be positive")


@dataclass
class _Observation:
    at: datetime
    source: str
    label: FeedbackLabel


@dataclass
class CanaryResult:
    """Outcome of evaluating the model against committed ground truth."""

    evaluated: int
    correct: int
    accuracy: float
    baseline: float
    degraded: bool

    @property
    def summary(self) -> str:
        return (
            f"{self.correct}/{self.evaluated} correct "
            f"(accuracy {self.accuracy:.3f}, baseline {self.baseline:.3f})"
        )


@dataclass
class PoisoningGuard:
    """Gatekeeper for every update that reaches the model."""

    config: GuardConfig = field(default_factory=GuardConfig)
    _history: deque[_Observation] = field(default_factory=deque, init=False)
    _frozen_reason: str | None = field(default=None, init=False)

    # -- freezing ---------------------------------------------------------

    @property
    def frozen(self) -> bool:
        return self._frozen_reason is not None

    @property
    def frozen_reason(self) -> str | None:
        return self._frozen_reason

    def freeze(self, reason: str) -> None:
        """Stop accepting updates. Intentionally not auto-reversible.

        A freeze means something looked wrong enough that a human should decide
        whether learning resumes. Thawing on a timer would defeat the point.
        """
        self._frozen_reason = reason

    def thaw(self) -> None:
        self._frozen_reason = None

    # -- admission --------------------------------------------------------

    def _prune(self, now: datetime) -> None:
        cutoff = now - self.config.window
        while self._history and self._history[0].at < cutoff:
            self._history.popleft()

    def evaluate(
        self,
        *,
        label: FeedbackLabel,
        source: str,
        identity_verified: bool,
        now: datetime | None = None,
    ) -> GuardDecision:
        """Decide whether this feedback may train the model, and how much."""
        moment = now or datetime.now(UTC)
        self._prune(moment)

        if self.frozen:
            return GuardDecision(
                accepted=False,
                reason=RejectionReason.TRAINING_FROZEN,
                detail=self._frozen_reason,
            )

        if label not in TRAINABLE_LABELS:
            return GuardDecision(
                accepted=False,
                reason=RejectionReason.NOT_TRAINABLE,
                detail=f"label {label.value!r} carries no training signal",
            )

        weight = self.config.verified_weight if identity_verified else self.config.unverified_weight
        if weight <= 0.0:
            return GuardDecision(
                accepted=False,
                reason=RejectionReason.UNVERIFIED_IDENTITY,
                detail="feedback from an unverified principal cannot train the model",
            )

        same_source = [item for item in self._history if item.source == source]

        matching_label = sum(1 for item in same_source if item.label == label)
        if matching_label >= self.config.label_flood_threshold:
            return GuardDecision(
                accepted=False,
                reason=RejectionReason.LABEL_FLOOD,
                detail=(
                    f"source supplied {matching_label} {label.value!r} labels "
                    f"within {self.config.window}"
                ),
            )

        total = len(self._history)
        if total >= self.config.min_updates_before_capping:
            # Share is measured as it would stand *after* accepting this one,
            # so the cap cannot be walked past one update at a time.
            projected = (len(same_source) + 1) / (total + 1)
            if projected > self.config.max_source_share:
                return GuardDecision(
                    accepted=False,
                    reason=RejectionReason.INFLUENCE_CAP,
                    detail=(
                        f"source would hold {projected:.1%} of updates in window, "
                        f"cap is {self.config.max_source_share:.1%}"
                    ),
                )

        return GuardDecision(accepted=True, weight=weight)

    def record(self, *, label: FeedbackLabel, source: str, now: datetime | None = None) -> None:
        """Note an accepted update so it counts toward the window limits."""
        self._history.append(_Observation(at=now or datetime.now(UTC), source=source, label=label))

    def window_stats(self, now: datetime | None = None) -> dict[str, int]:
        """Update counts per source in the current window, for observability."""
        self._prune(now or datetime.now(UTC))
        counts: dict[str, int] = {}
        for item in self._history:
            counts[item.source] = counts.get(item.source, 0) + 1
        return dict(sorted(counts.items()))


def evaluate_canary(
    predictions: Sequence[tuple[float, float]],
    *,
    baseline: float,
    decision_threshold: float = 0.5,
    tolerance: float = 0.05,
) -> CanaryResult:
    """Score the model against immutable ground truth.

    `predictions` is a sequence of (predicted_probability, expected_label)
    pairs drawn from the committed detection corpus. Degradation is measured
    against `baseline` — the accuracy recorded when the corpus was last
    accepted — with `tolerance` absolute slack for ordinary drift.

    A learned detector that has quietly stopped recognizing known-bad traffic is
    worse than no learned detector at all, because it looks like it is working.
    """
    if not predictions:
        return CanaryResult(evaluated=0, correct=0, accuracy=0.0, baseline=baseline, degraded=False)

    correct = sum(
        1
        for probability, expected in predictions
        if (1.0 if probability >= decision_threshold else 0.0) == expected
    )
    accuracy = correct / len(predictions)
    return CanaryResult(
        evaluated=len(predictions),
        correct=correct,
        accuracy=accuracy,
        baseline=baseline,
        degraded=accuracy < baseline - tolerance,
    )


__all__ = [
    "TRAINABLE_LABELS",
    "CanaryResult",
    "GuardConfig",
    "GuardDecision",
    "PoisoningGuard",
    "RejectionReason",
    "evaluate_canary",
]
