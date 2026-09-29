"""Adaptive detection: a detector that keeps learning from analyst feedback.

Threats are open-ended, so a detector built only from fixed rules is always
describing last month's attacks. This package adds a layer that updates from the
labels analysts are already producing through the feedback API, without giving
that layer any authority it should not have.

The three pieces, and why each exists:

- `features`  — deterministic, privacy-preserving, bounded feature extraction.
                Raw identifiers never reach a weight; the parameter count does
                not grow with the number of hosts observed.
- `online`    — incremental classifiers, pure standard library. An AdaGrad
                logistic model by default, a from-scratch one-hidden-layer
                network when the data justifies it.
- `guard`     — the controls that make continuous learning safe: trust
                weighting on verified identity, influence caps, flood
                detection, and a canary against committed ground truth.

`engine.AdaptiveDetector` composes them. Its output is advisory in the sense
`docs/AI_MODEL_GOVERNANCE.md` means: it informs an analyst and never enforces.
"""

from __future__ import annotations

from .engine import (
    STATE_VERSION,
    AdaptiveAssessment,
    AdaptiveDetector,
    LearningOutcome,
    trainable_labels,
)
from .features import HASH_DIMENSION, extract_features, hash_to_dense
from .guard import (
    TRAINABLE_LABELS,
    CanaryResult,
    GuardConfig,
    GuardDecision,
    PoisoningGuard,
    RejectionReason,
    evaluate_canary,
)
from .online import (
    OnlineClassifier,
    OnlineLogisticRegression,
    OnlineMLP,
    model_from_state,
    sigmoid,
)

__all__ = [
    "HASH_DIMENSION",
    "STATE_VERSION",
    "TRAINABLE_LABELS",
    "AdaptiveAssessment",
    "AdaptiveDetector",
    "CanaryResult",
    "GuardConfig",
    "GuardDecision",
    "LearningOutcome",
    "OnlineClassifier",
    "OnlineLogisticRegression",
    "OnlineMLP",
    "PoisoningGuard",
    "RejectionReason",
    "evaluate_canary",
    "extract_features",
    "hash_to_dense",
    "model_from_state",
    "sigmoid",
    "trainable_labels",
]
