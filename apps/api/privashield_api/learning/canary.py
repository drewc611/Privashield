"""Load the committed ground truth the detector checks itself against.

Kept in `evaluation/` with the other corpora, and loaded rather than generated,
because ADR-0004 makes this file load-bearing: it is the only control that bounds
poisoning damage, and a corpus the code could synthesise would be a corpus an
attacker could influence.

A missing or unreadable corpus is not silently tolerated. It means learning would
run with no defense, and `AdaptiveDetector.status()` reports `canary_enabled`
false so that state is visible rather than assumed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..schemas import SecurityEvent
from .engine import AdaptiveDetector

#: Default location, relative to the repository root.
DEFAULT_CANARY_PATH = Path("evaluation/adaptive-canary.json")
SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0"})


class CanaryCorpusError(ValueError):
    """The corpus could not be loaded, so learning has no ground truth."""


@dataclass(frozen=True)
class CanaryCorpus:
    """Labelled events plus the thresholds the corpus itself declares."""

    cases: tuple[tuple[SecurityEvent, float], ...]
    decision_threshold: float
    tolerance: float

    def __len__(self) -> int:
        return len(self.cases)

    @property
    def is_balanced(self) -> bool:
        """Whether both labels are present.

        A one-sided corpus cannot detect blinding: a model that calls everything
        malicious scores perfectly against an all-malicious corpus.
        """
        labels = {label for _, label in self.cases}
        return {0.0, 1.0} <= labels


def load_canary_corpus(path: Path | str = DEFAULT_CANARY_PATH) -> CanaryCorpus:
    """Read and validate the canary corpus."""
    location = Path(path)
    try:
        raw: Any = json.loads(location.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CanaryCorpusError(f"canary corpus unreadable at {location}") from exc
    except json.JSONDecodeError as exc:
        raise CanaryCorpusError(f"canary corpus at {location} is not valid JSON") from exc

    version = raw.get("schema_version")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise CanaryCorpusError(
            f"unsupported canary corpus schema_version {version!r} "
            f"(this build reads {sorted(SUPPORTED_SCHEMA_VERSIONS)})"
        )

    entries = raw.get("cases")
    if not isinstance(entries, list) or not entries:
        raise CanaryCorpusError("canary corpus contains no cases")

    cases: list[tuple[SecurityEvent, float]] = []
    for entry in entries:
        expected = entry.get("expected")
        if expected not in (0.0, 1.0):
            raise CanaryCorpusError(
                f"case {entry.get('id')!r} has expected={expected!r}; "
                "ground truth must be 0.0 or 1.0, never a guess"
            )
        cases.append((SecurityEvent(**entry["event"]), float(expected)))

    corpus = CanaryCorpus(
        cases=tuple(cases),
        decision_threshold=float(raw.get("decision_threshold", 0.5)),
        tolerance=float(raw.get("tolerance", 0.05)),
    )
    if not corpus.is_balanced:
        raise CanaryCorpusError(
            "canary corpus needs both malicious and benign cases; a one-sided "
            "corpus cannot detect a detector that has been blinded"
        )
    return corpus


def arm_detector(
    detector: AdaptiveDetector,
    corpus: CanaryCorpus,
    *,
    interval: int = 20,
) -> AdaptiveDetector:
    """Attach ground truth to a detector and record its starting accuracy.

    Arming is a separate step from constructing the detector because the baseline
    has to be measured, not assumed. A detector carrying a corpus it has never
    been scored against would report `canary_enabled` true while having no bar to
    fall below, which is the worst of both: the defense looks present and does
    nothing.
    """
    detector.canary_corpus = list(corpus.cases)
    detector.canary_interval = interval
    result = detector.run_canary(
        list(corpus.cases), tolerance=corpus.tolerance, freeze_on_degradation=False
    )
    detector.accept_canary_baseline(result)
    return detector


def learning_blocked_reason(
    detector: AdaptiveDetector, *, learning_enabled: bool, auth_mode: str
) -> str | None:
    """Why feedback cannot train the model right now, or None if it can.

    One predicate, used by both the status endpoint and the feedback path, so
    what an operator reads cannot drift from what actually happens.
    """
    if not learning_enabled:
        return "learning is disabled in configuration"
    if auth_mode == "disabled":
        return (
            "authentication is disabled, so no analyst is a verified principal and the "
            "guard weights every update at zero"
        )
    if not detector.canary_corpus:
        return (
            "no canary corpus is armed, so learning would run with no defense against "
            "poisoning (ADR-0004)"
        )
    if detector.guard.frozen:
        return detector.guard.frozen_reason
    return None


__all__ = [
    "DEFAULT_CANARY_PATH",
    "SUPPORTED_SCHEMA_VERSIONS",
    "CanaryCorpus",
    "CanaryCorpusError",
    "arm_detector",
    "learning_blocked_reason",
    "load_canary_corpus",
]
