from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from privashield_api.feedback_models import AnalystFeedback, FeedbackLabel, FeedbackTargetType
from privashield_api.learning.engine import (
    STATE_VERSION,
    AdaptiveDetector,
    trainable_labels,
)
from privashield_api.learning.guard import GuardConfig, PoisoningGuard, RejectionReason
from privashield_api.learning.online import OnlineLogisticRegression, OnlineMLP
from privashield_api.schemas import EventSource, SecurityEvent, Severity

NOW = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)


def event(summary: str = "Suspicious outbound TLS", **overrides: object) -> SecurityEvent:
    defaults: dict[str, object] = {
        "timestamp": NOW,
        "source": EventSource.SURICATA,
        "event_type": "alert",
        "severity": Severity.HIGH,
        "summary": summary,
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)  # type: ignore[arg-type]


def feedback(
    label: FeedbackLabel = FeedbackLabel.TRUE_POSITIVE, *, verified: bool = True
) -> AnalystFeedback:
    return AnalystFeedback(
        target_type=FeedbackTargetType.EVENT,
        target_id=uuid4(),
        label=label,
        identity_verified=verified,
    )


MALICIOUS = event("RDP brute force from external host", severity=Severity.CRITICAL, dst_port=3389)
BENIGN = event("Scheduled backup completed", severity=Severity.INFO, dst_port=443)


def train(detector: AdaptiveDetector, rounds: int = 30) -> None:
    for index in range(rounds):
        source = f"analyst-{index % 8}"
        detector.learn(MALICIOUS, feedback(FeedbackLabel.TRUE_POSITIVE), source=source, now=NOW)
        detector.learn(BENIGN, feedback(FeedbackLabel.BENIGN), source=source, now=NOW)


# --------------------------------------------------------------------------
# The authority boundary — the constraint that shapes the design
# --------------------------------------------------------------------------


def test_every_assessment_is_marked_advisory() -> None:
    # AI_MODEL_GOVERNANCE.md forbids a model gaining enforcement authority.
    # This asserts that is a property of the code, not only of the document.
    assert AdaptiveDetector().score(MALICIOUS).advisory_only is True


def test_advisory_flag_survives_training() -> None:
    detector = AdaptiveDetector()
    train(detector)
    assert detector.score(MALICIOUS).advisory_only is True
    assert detector.status()["advisory_only"] is True


def test_assessment_is_frozen_so_callers_cannot_clear_the_flag() -> None:
    assessment = AdaptiveDetector().score(MALICIOUS)
    with pytest.raises(FrozenInstanceError):
        assessment.advisory_only = False  # type: ignore[misc]


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


def test_untrained_detector_reports_no_confidence() -> None:
    assessment = AdaptiveDetector().score(MALICIOUS)
    assert assessment.score == pytest.approx(0.5)
    assert assessment.confidence == pytest.approx(0.0)


def test_confidence_grows_as_the_model_commits() -> None:
    detector = AdaptiveDetector()
    before = detector.score(MALICIOUS).confidence
    train(detector, rounds=60)
    assert detector.score(MALICIOUS).confidence > before


def test_assessment_records_model_provenance() -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=5)
    assessment = detector.score(MALICIOUS)
    assert assessment.model_kind == "online_logistic_regression"
    assert assessment.model_updates == 10


def test_linear_model_explains_its_score() -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=40)
    assessment = detector.score(MALICIOUS)
    assert assessment.contributions
    features = [name for name, _ in assessment.contributions]
    assert any("severity" in name or "port" in name for name in features)


def test_network_offers_no_per_feature_explanation() -> None:
    # Being honest about the trade-off rather than fabricating an explanation.
    detector = AdaptiveDetector(model=OnlineMLP(input_dimension=64, hidden_units=8))
    train(detector, rounds=10)
    assert detector.score(MALICIOUS).contributions == ()


def test_assessment_serializes_for_an_api_response() -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=10)
    payload = detector.score(MALICIOUS).to_dict()
    assert json.loads(json.dumps(payload))["advisory_only"] is True
    assert 0.0 <= payload["score"] <= 1.0


# --------------------------------------------------------------------------
# Learning
# --------------------------------------------------------------------------


def test_detector_learns_to_separate_classes() -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=60)
    assert detector.score(MALICIOUS).score > detector.score(BENIGN).score


def test_true_positive_raises_the_score_for_similar_events() -> None:
    detector = AdaptiveDetector()
    before = detector.score(MALICIOUS).score
    for index in range(30):
        detector.learn(
            MALICIOUS, feedback(FeedbackLabel.TRUE_POSITIVE), source=f"a-{index % 6}", now=NOW
        )
    assert detector.score(MALICIOUS).score > before


def test_false_positive_lowers_the_score() -> None:
    detector = AdaptiveDetector()
    before = detector.score(MALICIOUS).score
    for index in range(30):
        detector.learn(
            MALICIOUS, feedback(FeedbackLabel.FALSE_POSITIVE), source=f"a-{index % 6}", now=NOW
        )
    assert detector.score(MALICIOUS).score < before


def test_learning_reports_the_applied_weight_and_loss() -> None:
    outcome = AdaptiveDetector().learn(MALICIOUS, feedback(), source="analyst-a", now=NOW)
    assert outcome.applied
    assert outcome.weight == 1.0
    assert outcome.loss is not None and outcome.loss > 0.0


def test_undecided_feedback_is_refused_with_a_reason() -> None:
    outcome = AdaptiveDetector().learn(
        MALICIOUS, feedback(FeedbackLabel.NEEDS_REVIEW), source="analyst-a", now=NOW
    )
    assert not outcome.applied
    assert outcome.reason is RejectionReason.NOT_TRAINABLE
    assert outcome.to_dict()["reason"] == "not_trainable"


def test_unverified_feedback_never_reaches_the_model() -> None:
    detector = AdaptiveDetector()
    before = detector.score(MALICIOUS).score
    for _ in range(50):
        outcome = detector.learn(MALICIOUS, feedback(verified=False), source="anonymous", now=NOW)
        assert not outcome.applied
        assert outcome.reason is RejectionReason.UNVERIFIED_IDENTITY
    assert detector.score(MALICIOUS).score == before
    assert detector.model.updates == 0


def test_trainable_labels_are_the_decided_ones() -> None:
    assert set(trainable_labels()) == {
        FeedbackLabel.TRUE_POSITIVE,
        FeedbackLabel.FALSE_POSITIVE,
        FeedbackLabel.BENIGN,
    }


# --------------------------------------------------------------------------
# End-to-end poisoning scenario
# --------------------------------------------------------------------------


def test_rate_limits_alone_do_not_stop_a_determined_poisoner() -> None:
    """An honest negative result, recorded so nobody mistakes caps for a defense.

    The guard refuses the great majority of attempts, but the fraction that fits
    inside the influence cap is still enough to flip a well-trained model.
    Measured: against a 60-update model, 15 poisoned updates at a 20% cap take a
    0.99 score down to 0.27. Only a 5-10% cap holds, and that is too tight for a
    real analyst team. This is why the canary exists.
    """
    detector = AdaptiveDetector(
        guard=PoisoningGuard(
            config=GuardConfig(max_source_share=0.3, min_updates_before_capping=10)
        ),
        canary_corpus=None,  # deliberately disabled: this is the unprotected case
    )
    for index in range(60):
        detector.learn(
            MALICIOUS, feedback(FeedbackLabel.TRUE_POSITIVE), source=f"analyst-{index % 8}", now=NOW
        )
    assert detector.score(MALICIOUS).score > 0.8, "precondition: the team taught it this is bad"

    refused = sum(
        1
        for _ in range(200)
        if not detector.learn(
            MALICIOUS, feedback(FeedbackLabel.BENIGN), source="compromised", now=NOW
        ).applied
    )

    assert refused > 150, "the cap should still refuse the great majority of attempts"
    assert detector.score(MALICIOUS).score < 0.5, (
        "expected the unprotected model to be blinded; if this now passes, the "
        "rate limits improved and this test should be revisited"
    )


def test_the_canary_stops_the_poisoning_the_rate_limits_let_through() -> None:
    """The same attack, with ground truth wired in. This is the control that works."""
    detector = AdaptiveDetector(
        guard=PoisoningGuard(
            config=GuardConfig(max_source_share=0.3, min_updates_before_capping=10)
        ),
        canary_corpus=[(MALICIOUS, 1.0), (BENIGN, 0.0)],
        canary_interval=10,
    )
    train(detector, rounds=40)  # both classes, so the corpus is actually learned
    detector.accept_canary_baseline(detector.run_canary(detector.canary_corpus or []))
    assert detector.canary_baseline == 1.0, "precondition: the model gets both canary cases right"

    for _ in range(200):
        detector.learn(MALICIOUS, feedback(FeedbackLabel.BENIGN), source="compromised", now=NOW)

    assert detector.guard.frozen, "the canary should have halted learning"
    assert detector.score(MALICIOUS).score > 0.5, "the detector was blinded to a known attack"


def test_the_canary_freeze_names_what_went_wrong() -> None:
    detector = AdaptiveDetector(
        guard=PoisoningGuard(config=GuardConfig(max_source_share=1.0, label_flood_threshold=10000)),
        canary_corpus=[(MALICIOUS, 1.0), (BENIGN, 0.0)],
        canary_interval=5,
        canary_baseline=1.0,
    )
    for _ in range(60):
        detector.learn(MALICIOUS, feedback(FeedbackLabel.BENIGN), source="compromised", now=NOW)

    assert detector.guard.frozen
    reason = detector.guard.frozen_reason or ""
    assert "canary degraded" in reason
    assert "pending review" in reason


def test_learning_without_a_canary_is_visible_in_status() -> None:
    # An operator should be able to tell at a glance that the control is off.
    assert AdaptiveDetector().status()["canary_enabled"] is False
    protected = AdaptiveDetector(canary_corpus=[(MALICIOUS, 1.0)])
    assert protected.status()["canary_enabled"] is True


def test_poisoning_is_visible_in_the_status_snapshot() -> None:
    detector = AdaptiveDetector(
        guard=PoisoningGuard(config=GuardConfig(max_source_share=1.0, label_flood_threshold=1000))
    )
    for index in range(20):
        detector.learn(MALICIOUS, feedback(), source=f"analyst-{index % 4}", now=NOW)
    for _ in range(30):
        detector.learn(MALICIOUS, feedback(), source="suspicious", now=NOW)

    sources = detector.status()["window_sources"]
    assert sources["suspicious"] == 30
    # An operator can see one source dominating without reading the weights.
    assert max(sources, key=lambda name: sources[name]) == "suspicious"


# --------------------------------------------------------------------------
# Canary against committed ground truth
# --------------------------------------------------------------------------


def test_canary_passes_for_a_correctly_trained_model() -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=60)
    result = detector.run_canary([(MALICIOUS, 1.0), (BENIGN, 0.0)])
    assert result.accuracy == 1.0
    assert not result.degraded
    assert not detector.guard.frozen


def test_canary_freezes_learning_when_the_model_degrades() -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=60)
    detector.accept_canary_baseline(detector.run_canary([(MALICIOUS, 1.0), (BENIGN, 0.0)]))
    assert detector.canary_baseline == 1.0

    # Now the model has been turned against known ground truth.
    result = detector.run_canary([(MALICIOUS, 0.0), (BENIGN, 1.0)])
    assert result.degraded
    assert detector.guard.frozen
    assert detector.guard.frozen_reason is not None
    assert "canary degraded" in detector.guard.frozen_reason


def test_a_frozen_detector_stops_learning_entirely() -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=30)
    detector.guard.freeze("under investigation")
    before = detector.model.updates
    outcome = detector.learn(MALICIOUS, feedback(), source="analyst-a", now=NOW)
    assert not outcome.applied
    assert outcome.reason is RejectionReason.TRAINING_FROZEN
    assert detector.model.updates == before


def test_a_frozen_detector_still_scores() -> None:
    # Freezing halts learning, not detection. Losing detection because learning
    # looked suspect would turn a defensive control into an availability bug.
    detector = AdaptiveDetector()
    train(detector, rounds=40)
    expected = detector.score(MALICIOUS).score
    detector.guard.freeze("under investigation")
    assert detector.score(MALICIOUS).score == expected


def test_canary_can_report_without_freezing() -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=40)
    detector.canary_baseline = 1.0
    result = detector.run_canary([(MALICIOUS, 0.0)], freeze_on_degradation=False)
    assert result.degraded
    assert not detector.guard.frozen


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


def test_state_round_trip_preserves_scores(tmp_path: Path) -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=40)
    path = tmp_path / "model.json"
    detector.save(path)

    restored = AdaptiveDetector.load(path)
    assert restored.score(MALICIOUS).score == detector.score(MALICIOUS).score
    assert restored.score(BENIGN).score == detector.score(BENIGN).score
    assert restored.model.updates == detector.model.updates


def test_saved_state_is_plain_readable_json(tmp_path: Path) -> None:
    # Not a pickle: a security appliance must not execute arbitrary code when it
    # loads a model file, and an operator should be able to read the weights.
    detector = AdaptiveDetector()
    train(detector, rounds=5)
    path = tmp_path / "model.json"
    detector.save(path)

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["state_version"] == STATE_VERSION
    assert raw["model"]["kind"] == "online_logistic_regression"
    assert isinstance(raw["model"]["weights"], dict)


def test_save_creates_missing_parent_directories(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "deeper" / "model.json"
    AdaptiveDetector().save(path)
    assert path.exists()


def test_save_leaves_no_temporary_file_behind(tmp_path: Path) -> None:
    path = tmp_path / "model.json"
    AdaptiveDetector().save(path)
    assert [item.name for item in tmp_path.iterdir()] == ["model.json"]


def test_frozen_state_survives_a_restart(tmp_path: Path) -> None:
    # A freeze must not be cleared by restarting the service, or it is not a
    # control at all.
    detector = AdaptiveDetector()
    detector.guard.freeze("canary degraded during upgrade")
    path = tmp_path / "model.json"
    detector.save(path)

    restored = AdaptiveDetector.load(path)
    assert restored.guard.frozen
    assert restored.guard.frozen_reason == "canary degraded during upgrade"


def test_guard_configuration_survives_a_restart(tmp_path: Path) -> None:
    detector = AdaptiveDetector(
        guard=PoisoningGuard(
            config=GuardConfig(
                max_source_share=0.15,
                label_flood_threshold=7,
                window=timedelta(hours=6),
                unverified_weight=0.25,
            )
        )
    )
    path = tmp_path / "model.json"
    detector.save(path)

    config = AdaptiveDetector.load(path).guard.config
    assert config.max_source_share == 0.15
    assert config.label_flood_threshold == 7
    assert config.window == timedelta(hours=6)
    assert config.unverified_weight == 0.25


def test_canary_baseline_survives_a_restart(tmp_path: Path) -> None:
    detector = AdaptiveDetector(canary_baseline=0.93)
    path = tmp_path / "model.json"
    detector.save(path)
    assert AdaptiveDetector.load(path).canary_baseline == 0.93


def test_network_state_round_trips(tmp_path: Path) -> None:
    detector = AdaptiveDetector(model=OnlineMLP(input_dimension=64, hidden_units=8))
    train(detector, rounds=20)
    path = tmp_path / "model.json"
    detector.save(path)

    restored = AdaptiveDetector.load(path)
    assert isinstance(restored.model, OnlineMLP)
    assert restored.score(MALICIOUS).score == detector.score(MALICIOUS).score


def test_loading_an_unknown_state_version_is_refused() -> None:
    state = AdaptiveDetector().to_state()
    state["state_version"] = 99
    with pytest.raises(ValueError, match="unsupported adaptive detector state version"):
        AdaptiveDetector.from_state(state)


def test_restored_detector_keeps_learning(tmp_path: Path) -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=20)
    path = tmp_path / "model.json"
    detector.save(path)

    restored = AdaptiveDetector.load(path)
    before = restored.score(MALICIOUS).score
    for index in range(30):
        restored.learn(MALICIOUS, feedback(), source=f"analyst-{index % 8}", now=NOW)
    assert restored.score(MALICIOUS).score > before


# --------------------------------------------------------------------------
# Status snapshot
# --------------------------------------------------------------------------


def test_status_reports_operational_state() -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=10)
    status = detector.status()
    assert status["model_kind"] == "online_logistic_regression"
    assert status["updates"] == 20
    assert status["learning_frozen"] is False
    assert status["top_features"]


def test_status_surfaces_a_freeze_and_its_reason() -> None:
    detector = AdaptiveDetector()
    detector.guard.freeze("canary degraded: 2/10 correct")
    status = detector.status()
    assert status["learning_frozen"] is True
    assert "2/10 correct" in status["frozen_reason"]


def test_status_is_json_serializable() -> None:
    detector = AdaptiveDetector()
    train(detector, rounds=5)
    assert json.loads(json.dumps(detector.status()))["model_kind"]


def test_status_omits_feature_weights_for_the_network() -> None:
    detector = AdaptiveDetector(model=OnlineMLP(input_dimension=32, hidden_units=4))
    train(detector, rounds=5)
    assert detector.status()["top_features"] == []


def test_default_model_is_the_interpretable_one() -> None:
    # Choosing the explainable model by default is a deliberate decision, so it
    # should fail loudly if someone changes it without meaning to.
    assert isinstance(AdaptiveDetector().model, OnlineLogisticRegression)


def test_a_passing_canary_checkpoints_the_model() -> None:
    detector = AdaptiveDetector(canary_corpus=[(MALICIOUS, 1.0), (BENIGN, 0.0)], canary_interval=10)
    assert detector.trusted_model_state is None
    train(detector, rounds=20)
    assert detector.trusted_model_state is not None
    assert detector.status()["has_trusted_state"] is True


def test_rollback_discards_the_poisoned_updates() -> None:
    detector = AdaptiveDetector(
        guard=PoisoningGuard(config=GuardConfig(max_source_share=1.0, label_flood_threshold=10000)),
        canary_corpus=[(MALICIOUS, 1.0), (BENIGN, 0.0)],
        canary_interval=5,
    )
    train(detector, rounds=40)
    detector.accept_canary_baseline(detector.run_canary(detector.canary_corpus or []))
    clean_updates = detector.model.updates

    for _ in range(50):
        detector.learn(MALICIOUS, feedback(FeedbackLabel.BENIGN), source="compromised", now=NOW)

    assert detector.guard.frozen
    assert "rolled back" in (detector.guard.frozen_reason or "")
    # The checkpoint is the last state that *passed* ground truth, not the
    # pristine one, so some poison is retained by design. The guarantee is
    # narrower and more useful: whatever survives rollback still gets the
    # committed corpus right.
    assert detector.model.updates < clean_updates + 50, "poison should be partly discarded"
    assert detector.score(MALICIOUS).score > 0.5, "the restored model still sees the attack"
    recheck = detector.run_canary(detector.canary_corpus or [], freeze_on_degradation=False)
    assert not recheck.degraded


def test_rollback_is_honest_when_there_is_nothing_to_roll_back_to() -> None:
    # No corpus wired, so learning never checkpoints; then it is taught wrongly
    # and only afterwards checked against ground truth.
    detector = AdaptiveDetector(canary_baseline=1.0)
    assert detector.restore_trusted_state() is False
    for index in range(40):
        detector.learn(
            MALICIOUS, feedback(FeedbackLabel.BENIGN), source=f"analyst-{index % 8}", now=NOW
        )
    detector.run_canary([(MALICIOUS, 1.0)])
    assert "no verified state to roll back to" in (detector.guard.frozen_reason or "")


def test_trusted_state_survives_a_restart(tmp_path: Path) -> None:
    detector = AdaptiveDetector(canary_corpus=[(MALICIOUS, 1.0), (BENIGN, 0.0)], canary_interval=10)
    train(detector, rounds=20)
    path = tmp_path / "detector.json"
    detector.save(path)

    reloaded = AdaptiveDetector.load(path)
    assert reloaded.trusted_model_state == detector.trusted_model_state
    assert reloaded.restore_trusted_state() is True
