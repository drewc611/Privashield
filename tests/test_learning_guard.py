"""Tests for the controls that make continuous learning safe.

These read as attack scenarios rather than unit tests, because that is what they
are. Each one describes something an adversary would try against a detector that
trains itself on analyst feedback.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from privashield_api.feedback_models import FeedbackLabel
from privashield_api.learning.guard import (
    TRAINABLE_LABELS,
    GuardConfig,
    PoisoningGuard,
    RejectionReason,
    evaluate_canary,
)

NOW = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)


def guard(**overrides: object) -> PoisoningGuard:
    return PoisoningGuard(config=GuardConfig(**overrides))  # type: ignore[arg-type]


def admit(
    subject: PoisoningGuard,
    *,
    label: FeedbackLabel = FeedbackLabel.BENIGN,
    source: str = "analyst-a",
    verified: bool = True,
    now: datetime = NOW,
) -> object:
    decision = subject.evaluate(label=label, source=source, identity_verified=verified, now=now)
    if decision.accepted:
        subject.record(label=label, source=source, now=now)
    return decision


# --------------------------------------------------------------------------
# Which labels carry signal at all
# --------------------------------------------------------------------------


def test_decided_labels_map_to_training_targets() -> None:
    assert TRAINABLE_LABELS[FeedbackLabel.TRUE_POSITIVE] == 1.0
    assert TRAINABLE_LABELS[FeedbackLabel.FALSE_POSITIVE] == 0.0
    assert TRAINABLE_LABELS[FeedbackLabel.BENIGN] == 0.0


def test_needs_review_is_not_a_label() -> None:
    # Treating "I have not decided" as a decision teaches the model noise.
    assert FeedbackLabel.NEEDS_REVIEW not in TRAINABLE_LABELS
    decision = guard().evaluate(
        label=FeedbackLabel.NEEDS_REVIEW,
        source="analyst-a",
        identity_verified=True,
        now=NOW,
    )
    assert not decision.accepted
    assert decision.reason is RejectionReason.NOT_TRAINABLE


# --------------------------------------------------------------------------
# Attack: label the model from an unverified identity
# --------------------------------------------------------------------------


def test_unverified_feedback_cannot_train_by_default() -> None:
    decision = guard().evaluate(
        label=FeedbackLabel.BENIGN,
        source="anonymous",
        identity_verified=False,
        now=NOW,
    )
    assert not decision.accepted
    assert decision.reason is RejectionReason.UNVERIFIED_IDENTITY


def test_verified_feedback_carries_full_weight() -> None:
    decision = guard().evaluate(
        label=FeedbackLabel.BENIGN,
        source="analyst-a",
        identity_verified=True,
        now=NOW,
    )
    assert decision.accepted
    assert decision.weight == 1.0


def test_operator_may_admit_unverified_feedback_at_reduced_weight() -> None:
    # Permitted, but it has to be a deliberate configuration change.
    decision = guard(unverified_weight=0.2).evaluate(
        label=FeedbackLabel.BENIGN,
        source="anonymous",
        identity_verified=False,
        now=NOW,
    )
    assert decision.accepted
    assert decision.weight == 0.2


def test_unverified_weight_cannot_exceed_verified_weight() -> None:
    with pytest.raises(ValueError, match="unverified_weight"):
        GuardConfig(verified_weight=0.5, unverified_weight=0.9)


# --------------------------------------------------------------------------
# Attack: one compromised account floods the model with labels
# --------------------------------------------------------------------------


def test_a_single_source_cannot_exceed_its_influence_share() -> None:
    subject = guard(max_source_share=0.5, min_updates_before_capping=4)
    for index in range(10):
        admit(subject, source=f"analyst-{index}")

    # The attacker now tries to out-vote the team from one account.
    accepted = 0
    for _ in range(20):
        decision = admit(subject, source="compromised")
        if getattr(decision, "accepted", False):
            accepted += 1

    counts = subject.window_stats(now=NOW)
    share = counts["compromised"] / sum(counts.values())
    assert share <= 0.5, f"compromised source reached {share:.1%} of updates"
    assert accepted < 20


def test_influence_cap_is_measured_after_the_pending_update() -> None:
    # Measuring share before accepting would let an attacker step past the cap
    # one update at a time, since each individual update looks compliant.
    subject = guard(max_source_share=0.25, min_updates_before_capping=3)
    for index in range(9):
        admit(subject, source=f"analyst-{index}")
    for _ in range(5):
        admit(subject, source="compromised")
    counts = subject.window_stats(now=NOW)
    assert counts.get("compromised", 0) / sum(counts.values()) <= 0.25


def test_cap_is_not_enforced_before_a_meaningful_sample_exists() -> None:
    # Otherwise the first analyst to give feedback trips the cap immediately.
    subject = guard(max_source_share=0.1, min_updates_before_capping=50)
    for _ in range(20):
        decision = admit(subject, source="only-analyst")
        assert getattr(decision, "accepted", False)


def test_influence_rejection_explains_itself() -> None:
    subject = guard(max_source_share=0.2, min_updates_before_capping=2)
    for index in range(8):
        admit(subject, source=f"analyst-{index}")
    for _ in range(4):
        admit(subject, source="noisy")
    decision = subject.evaluate(
        label=FeedbackLabel.BENIGN, source="noisy", identity_verified=True, now=NOW
    )
    assert not decision.accepted
    assert decision.reason is RejectionReason.INFLUENCE_CAP
    assert decision.detail is not None and "cap is" in decision.detail


# --------------------------------------------------------------------------
# Attack: patient automated poisoning with one repeated label
# --------------------------------------------------------------------------


def test_repeated_identical_labels_are_detected_as_a_flood() -> None:
    subject = guard(label_flood_threshold=10, max_source_share=1.0)
    for _ in range(10):
        admit(subject, label=FeedbackLabel.BENIGN, source="bot")
    decision = subject.evaluate(
        label=FeedbackLabel.BENIGN, source="bot", identity_verified=True, now=NOW
    )
    assert not decision.accepted
    assert decision.reason is RejectionReason.LABEL_FLOOD


def test_flood_detection_is_per_label_not_per_source() -> None:
    # An analyst genuinely working a mixed queue must not be mistaken for a bot.
    # Counting is per (source, label), so rotating through decisions keeps every
    # individual label count below the threshold even as the total climbs past it.
    labels = [FeedbackLabel.TRUE_POSITIVE, FeedbackLabel.FALSE_POSITIVE, FeedbackLabel.BENIGN]
    subject = guard(label_flood_threshold=5, max_source_share=1.0)
    for index in range(12):
        decision = admit(subject, label=labels[index % 3], source="busy-analyst")
        assert getattr(decision, "accepted", False), f"rejected at {index}"
    # Twelve accepted, four of each label — none reached the threshold of five.
    assert sum(subject.window_stats(now=NOW).values()) == 12

    # The same source repeating one label trips at the threshold instead.
    flooder = guard(label_flood_threshold=5, max_source_share=1.0)
    accepted = sum(
        1
        for _ in range(12)
        if getattr(admit(flooder, label=FeedbackLabel.BENIGN, source="bot"), "accepted", False)
    )
    assert accepted == 5


def test_limits_only_apply_within_the_window() -> None:
    subject = guard(label_flood_threshold=3, max_source_share=1.0, window=timedelta(hours=1))
    for _ in range(3):
        admit(subject, source="bot", now=NOW)
    blocked = subject.evaluate(
        label=FeedbackLabel.BENIGN, source="bot", identity_verified=True, now=NOW
    )
    assert not blocked.accepted

    # Two hours later the old observations have aged out.
    later = NOW + timedelta(hours=2)
    allowed = subject.evaluate(
        label=FeedbackLabel.BENIGN, source="bot", identity_verified=True, now=later
    )
    assert allowed.accepted


# --------------------------------------------------------------------------
# Freezing
# --------------------------------------------------------------------------


def test_a_frozen_guard_refuses_everything() -> None:
    subject = guard()
    subject.freeze("canary degraded")
    decision = subject.evaluate(
        label=FeedbackLabel.TRUE_POSITIVE,
        source="analyst-a",
        identity_verified=True,
        now=NOW,
    )
    assert not decision.accepted
    assert decision.reason is RejectionReason.TRAINING_FROZEN
    assert decision.detail == "canary degraded"


def test_freezing_does_not_expire_on_its_own() -> None:
    # A freeze means a human should look. Thawing on a timer defeats that.
    subject = guard(window=timedelta(minutes=1))
    subject.freeze("suspected poisoning")
    much_later = NOW + timedelta(days=30)
    decision = subject.evaluate(
        label=FeedbackLabel.BENIGN, source="analyst-a", identity_verified=True, now=much_later
    )
    assert not decision.accepted
    assert subject.frozen


def test_thaw_restores_learning() -> None:
    subject = guard()
    subject.freeze("investigating")
    subject.thaw()
    assert not subject.frozen
    assert subject.frozen_reason is None
    assert subject.evaluate(
        label=FeedbackLabel.BENIGN, source="analyst-a", identity_verified=True, now=NOW
    ).accepted


# --------------------------------------------------------------------------
# Canary against committed ground truth
# --------------------------------------------------------------------------


def test_canary_scores_agreement_with_ground_truth() -> None:
    result = evaluate_canary([(0.9, 1.0), (0.8, 1.0), (0.1, 0.0), (0.2, 0.0)], baseline=0.0)
    assert result.evaluated == 4
    assert result.correct == 4
    assert result.accuracy == 1.0
    assert not result.degraded


def test_canary_flags_a_model_that_stopped_recognizing_known_bad() -> None:
    # The scenario poisoning produces: known-malicious corpus entries now score
    # benign. This is the control that bounds the damage.
    result = evaluate_canary([(0.1, 1.0), (0.2, 1.0), (0.1, 1.0), (0.3, 0.0)], baseline=0.95)
    assert result.accuracy == 0.25
    assert result.degraded


def test_canary_tolerates_ordinary_drift() -> None:
    result = evaluate_canary(
        [(0.9, 1.0), (0.9, 1.0), (0.9, 1.0), (0.6, 0.0)], baseline=0.80, tolerance=0.10
    )
    assert result.accuracy == 0.75
    assert not result.degraded


def test_canary_handles_an_empty_corpus() -> None:
    result = evaluate_canary([], baseline=0.9)
    assert result.evaluated == 0
    assert not result.degraded


def test_canary_decision_threshold_is_configurable() -> None:
    predictions = [(0.6, 1.0), (0.4, 0.0)]
    assert evaluate_canary(predictions, baseline=0.0, decision_threshold=0.5).accuracy == 1.0
    assert evaluate_canary(predictions, baseline=0.0, decision_threshold=0.7).accuracy == 0.5


def test_canary_summary_is_human_readable() -> None:
    result = evaluate_canary([(0.9, 1.0), (0.1, 1.0)], baseline=0.9)
    assert "1/2 correct" in result.summary


# --------------------------------------------------------------------------
# Configuration validation and observability
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"max_source_share": 0.0}, "max_source_share"),
        ({"max_source_share": 1.5}, "max_source_share"),
        ({"window": timedelta(0)}, "window"),
        ({"unverified_weight": -0.1}, "unverified_weight"),
    ],
)
def test_rejects_invalid_configuration(kwargs: dict[str, object], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        GuardConfig(**kwargs)  # type: ignore[arg-type]


def test_window_stats_report_per_source_counts() -> None:
    subject = guard(max_source_share=1.0)
    for _ in range(3):
        admit(subject, source="analyst-a")
    for _ in range(2):
        admit(subject, source="analyst-b")
    assert subject.window_stats(now=NOW) == {"analyst-a": 3, "analyst-b": 2}


def test_window_stats_drop_observations_outside_the_window() -> None:
    subject = guard(window=timedelta(hours=1), max_source_share=1.0)
    admit(subject, source="analyst-a", now=NOW)
    assert subject.window_stats(now=NOW + timedelta(hours=2)) == {}


def test_rejected_feedback_is_not_recorded_against_the_window() -> None:
    # Otherwise a rejected flood would still consume the team's influence budget.
    subject = guard()
    subject.evaluate(
        label=FeedbackLabel.NEEDS_REVIEW,
        source="analyst-a",
        identity_verified=True,
        now=NOW,
    )
    assert subject.window_stats(now=NOW) == {}
