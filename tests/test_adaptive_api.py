from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from privashield_api.config import Settings
from privashield_api.learning.canary import (
    CanaryCorpusError,
    arm_detector,
    load_canary_corpus,
)
from privashield_api.learning.engine import AdaptiveDetector
from privashield_api.main import create_app


def client(**overrides: object) -> TestClient:
    settings: dict[str, object] = {
        "database_enabled": False,
        "nats_enabled": False,
        "ollama_enabled": False,
        "audit_path": None,
        "environment": "test",
    }
    settings.update(overrides)
    return TestClient(create_app(Settings(**settings)))  # type: ignore[arg-type]


def ingest_authenticated(
    api: TestClient, headers: dict[str, str], **overrides: object
) -> dict[str, Any]:
    return ingest(api, _headers=headers, **overrides)


def ingest(api: TestClient, **overrides: object) -> dict[str, Any]:
    payload: dict[str, object] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "suricata",
        "event_type": "alert",
        "severity": "critical",
        "src_ip": "198.51.100.23",
        "dst_ip": "10.0.4.17",
        "dst_port": 3389,
        "summary": "Repeated failed RDP authentication from external host",
    }
    headers = overrides.pop("_headers", None)
    payload.update(overrides)
    response = api.post(
        "/api/v1/events/ingest",
        json=payload,
        headers=headers,
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


# --------------------------------------------------------------------------
# The canary corpus is load-bearing, so it is validated rather than trusted
# --------------------------------------------------------------------------


def test_the_committed_canary_corpus_loads() -> None:
    corpus = load_canary_corpus()
    assert len(corpus) >= 8
    assert corpus.is_balanced


def test_a_one_sided_corpus_is_refused(tmp_path: Path) -> None:
    """A corpus of only malicious cases cannot detect a blinded detector.

    A model that calls everything malicious scores perfectly against it, so
    accepting one would arm a defense that measures nothing.
    """
    path = tmp_path / "one-sided.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "only-bad",
                        "expected": 1.0,
                        "event": {
                            "timestamp": "2026-09-29T00:00:00Z",
                            "source": "suricata",
                            "event_type": "alert",
                            "severity": "critical",
                            "summary": "bad thing",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(CanaryCorpusError, match="one-sided"):
        load_canary_corpus(path)


def test_a_hedged_label_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "hedged.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "maybe",
                        "expected": 0.7,
                        "event": {
                            "timestamp": "2026-09-29T00:00:00Z",
                            "source": "suricata",
                            "event_type": "alert",
                            "severity": "high",
                            "summary": "unclear",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(CanaryCorpusError, match="never a guess"):
        load_canary_corpus(path)


def test_an_unknown_schema_version_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "future.json"
    path.write_text(json.dumps({"schema_version": "9.9", "cases": []}), encoding="utf-8")
    with pytest.raises(CanaryCorpusError, match="schema_version"):
        load_canary_corpus(path)


def test_a_missing_corpus_is_refused(tmp_path: Path) -> None:
    with pytest.raises(CanaryCorpusError, match="unreadable"):
        load_canary_corpus(tmp_path / "absent.json")


def test_arming_measures_the_baseline_rather_than_assuming_it() -> None:
    corpus = load_canary_corpus()
    detector = arm_detector(AdaptiveDetector(), corpus)
    snapshot = detector.status()
    assert snapshot["canary_enabled"] is True
    assert snapshot["has_trusted_state"] is True
    # An untrained model predicts 0.5 for everything, which at a 0.5 threshold
    # calls every case malicious: exactly half right on a balanced corpus.
    assert snapshot["canary_baseline"] == 0.5


# --------------------------------------------------------------------------
# Status
# --------------------------------------------------------------------------


def test_status_reports_the_canary_as_armed() -> None:
    with client() as api:
        body = api.get("/api/v1/learning/status").json()
    assert body["canary_enabled"] is True
    assert body["has_trusted_state"] is True
    assert body["advisory_only"] is True
    assert body["learning_frozen"] is False


def test_status_reports_learning_off_by_default() -> None:
    # A self-training detector is a trust-boundary change (ADR-0004), so it is
    # the operator's decision rather than a default.
    with client() as api:
        body = api.get("/api/v1/learning/status").json()
    assert body["learning_enabled"] is False
    assert body["scoring_enabled"] is True


def test_status_makes_a_missing_canary_visible() -> None:
    # The dangerous configuration is learning with no ground truth, so it must be
    # readable rather than assumed.
    with client(adaptive_canary_path="evaluation/does-not-exist.json") as api:
        body = api.get("/api/v1/learning/status").json()
    assert body["canary_enabled"] is False


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


def test_an_event_can_be_scored() -> None:
    with client() as api:
        event = ingest(api)
        response = api.get(f"/api/v1/learning/score/{event['id']}")
    assert response.status_code == 200
    body = response.json()
    assert body["event_id"] == event["id"]
    assert 0.0 <= body["score"] <= 1.0
    assert body["advisory_only"] is True


def test_an_untrained_score_reports_no_confidence() -> None:
    with client() as api:
        event = ingest(api)
        body = api.get(f"/api/v1/learning/score/{event['id']}").json()
    assert body["score"] == pytest.approx(0.5)
    assert body["confidence"] == pytest.approx(0.0)


def test_scoring_an_unknown_event_is_a_404() -> None:
    with client() as api:
        response = api.get(f"/api/v1/learning/score/{uuid4()}")
    assert response.status_code == 404


def test_scoring_can_be_switched_off() -> None:
    with client(adaptive_scoring_enabled=False) as api:
        event = ingest(api)
        response = api.get(f"/api/v1/learning/score/{event['id']}")
    assert response.status_code == 503


# --------------------------------------------------------------------------
# Feedback as a control loop
# --------------------------------------------------------------------------


def test_feedback_does_not_train_the_model_when_learning_is_off() -> None:
    with client() as api:
        event = ingest(api)
        api.post(
            "/api/v1/feedback",
            json={"target_type": "event", "target_id": event["id"], "label": "true_positive"},
        )
        body = api.get("/api/v1/learning/status").json()
    assert body["updates"] == 0


def test_disabled_authentication_blocks_learning_and_says_so() -> None:
    """The trap this exists to surface.

    With authentication disabled every principal is unverified, so the guard
    weights each update at zero and nothing ever trains. An operator who set the
    flag would otherwise see `learning_enabled: true`, watch nothing happen, and
    get no explanation.
    """
    with client(adaptive_learning_enabled=True) as api:
        event = ingest(api)
        api.post(
            "/api/v1/feedback",
            json={"target_type": "event", "target_id": event["id"], "label": "true_positive"},
        )
        body = api.get("/api/v1/learning/status").json()

    assert body["learning_enabled"] is True
    assert body["learning_effective"] is False
    assert "authentication is disabled" in (body["learning_blocked_reason"] or "")
    assert body["updates"] == 0, "unverified feedback must never reach the weights"


def test_learning_is_blocked_when_no_canary_is_armed() -> None:
    # ADR-0004: the canary is the only control that bounds poisoning damage, so
    # learning without one is refused rather than merely reported.
    with client(
        adaptive_learning_enabled=True,
        auth_mode="local",
        bootstrap_admin_token="test-admin-token",
        adaptive_canary_path="evaluation/does-not-exist.json",
    ) as api:
        body = api.get(
            "/api/v1/learning/status", headers={"Authorization": "Bearer test-admin-token"}
        ).json()
    assert body["learning_effective"] is False
    assert "no canary corpus is armed" in (body["learning_blocked_reason"] or "")


def test_learning_is_effective_once_identities_are_verified_and_the_canary_is_armed() -> None:
    with client(
        adaptive_learning_enabled=True,
        auth_mode="local",
        bootstrap_admin_token="test-admin-token",
    ) as api:
        body = api.get(
            "/api/v1/learning/status", headers={"Authorization": "Bearer test-admin-token"}
        ).json()
    assert body["learning_effective"] is True
    assert body["learning_blocked_reason"] is None


def test_verified_feedback_trains_the_model() -> None:
    with client(
        adaptive_learning_enabled=True,
        auth_mode="local",
        bootstrap_admin_token="test-admin-token",
    ) as api:
        headers = {"Authorization": "Bearer test-admin-token"}
        event = ingest_authenticated(api, headers)
        response = api.post(
            "/api/v1/feedback",
            json={"target_type": "event", "target_id": event["id"], "label": "true_positive"},
            headers=headers,
        )
        assert response.status_code == 201, response.text
        body = api.get("/api/v1/learning/status", headers=headers).json()
    assert body["updates"] == 1, "verified feedback did not reach the model"


def test_verified_training_moves_the_score_for_similar_events() -> None:
    with client(
        adaptive_learning_enabled=True,
        auth_mode="local",
        bootstrap_admin_token="test-admin-token",
    ) as api:
        headers = {"Authorization": "Bearer test-admin-token"}
        event = ingest_authenticated(api, headers)
        before = api.get(f"/api/v1/learning/score/{event['id']}", headers=headers).json()["score"]
        for _ in range(25):
            other = ingest_authenticated(api, headers)
            api.post(
                "/api/v1/feedback",
                json={"target_type": "event", "target_id": other["id"], "label": "true_positive"},
                headers=headers,
            )
        after = api.get(f"/api/v1/learning/score/{event['id']}", headers=headers).json()["score"]
    assert after > before, "analyst feedback changed nothing"


def test_an_applied_update_is_recorded_in_the_audit_ledger() -> None:
    with client(
        adaptive_learning_enabled=True,
        auth_mode="local",
        bootstrap_admin_token="test-admin-token",
    ) as api:
        headers = {"Authorization": "Bearer test-admin-token"}
        event = ingest_authenticated(api, headers)
        api.post(
            "/api/v1/feedback",
            json={"target_type": "event", "target_id": event["id"], "label": "true_positive"},
            headers=headers,
        )
        entries = api.get("/api/v1/audit", headers=headers).json()

    applied = [entry for entry in entries if entry["action"] == "learning.update.applied"]
    assert applied, "an applied update left no trace"
    assert applied[-1]["resource_type"] == "adaptive_detector"


def test_a_refused_update_is_recorded_too() -> None:
    """A refusal is the audit-worthy fact, not just the successes.

    `needs_review` carries no training signal, so the guard declines it. Someone
    reviewing the model's history needs to see that the feedback existed and did
    not apply. The ledger stores a payload hash rather than the payload, so the
    action name is what carries the fact.
    """
    with client(
        adaptive_learning_enabled=True,
        auth_mode="local",
        bootstrap_admin_token="test-admin-token",
    ) as api:
        headers = {"Authorization": "Bearer test-admin-token"}
        event = ingest_authenticated(api, headers)
        api.post(
            "/api/v1/feedback",
            json={"target_type": "event", "target_id": event["id"], "label": "needs_review"},
            headers=headers,
        )
        entries = api.get("/api/v1/audit", headers=headers).json()

    refusals = [entry for entry in entries if entry["action"] == "learning.update.refused"]
    assert refusals, "a refused update left no trace"
    assert refusals[-1]["resource_id"] == event["id"]


# --------------------------------------------------------------------------
# Durability — a model that forgets on restart is not a learning model
# --------------------------------------------------------------------------


def test_status_reports_when_learned_state_is_not_durable() -> None:
    # The default has no state path, so everything learned is lost on restart.
    # That has to be readable rather than discovered after a month of training.
    with client() as api:
        body = api.get("/api/v1/learning/status").json()
    assert body["state_durable"] is False


def test_learning_survives_a_restart(tmp_path: Path) -> None:
    """The defect this closes: learned state only reached disk at clean shutdown.

    With no state path configured — the default — it never reached disk at all.
    """
    state = tmp_path / "detector.json"
    settings: dict[str, object] = {
        "adaptive_learning_enabled": True,
        "auth_mode": "local",
        "bootstrap_admin_token": "test-admin-token",
        "adaptive_state_path": str(state),
        "adaptive_canary_interval": 5,
        # One principal submits every label here, so both source bounds would
        # otherwise stop it: the share cap and the 20-update budget. Both are
        # exercised on their own below; this test is about persistence.
        "adaptive_max_source_share": 1.0,
        "adaptive_max_source_updates": 100,
    }
    headers = {"Authorization": "Bearer test-admin-token"}

    with client(**settings) as api:
        assert api.get("/api/v1/learning/status", headers=headers).json()["state_durable"] is True
        for _ in range(25):
            event = ingest_authenticated(api, headers)
            api.post(
                "/api/v1/feedback",
                json={"target_type": "event", "target_id": event["id"], "label": "true_positive"},
                headers=headers,
            )
        trained = api.get("/api/v1/learning/status", headers=headers).json()["updates"]

    assert trained == 25
    assert state.exists(), "learned state never reached disk"

    # A fresh process, as a restart would be.
    with client(**settings) as api:
        restored = api.get("/api/v1/learning/status", headers=headers).json()
    assert restored["updates"] == trained, "the model forgot everything on restart"


def test_a_checkpoint_lands_before_any_clean_shutdown(tmp_path: Path) -> None:
    """A crash must not cost the whole model, only the window since the last check.

    Checkpoints ride the canary: the state that passed ground truth is the state
    worth keeping, so the trusted checkpoint and the durable one are the same.
    """
    state = tmp_path / "detector.json"
    detector = arm_detector(AdaptiveDetector(), load_canary_corpus(), interval=5)
    detector.state_path = state
    assert detector.save_pending is True, "arming produces a verified state to keep"

    assert detector.flush() is True
    assert state.exists()
    assert detector.flush() is False, "a second flush with nothing owed must not rewrite"


def test_flush_is_a_no_op_without_a_state_path() -> None:
    detector = arm_detector(AdaptiveDetector(), load_canary_corpus())
    assert detector.state_path is None
    assert detector.save_pending is False
    assert detector.flush() is False


# --------------------------------------------------------------------------
# The influence cap interacts with team size, and that is easy to mistake for
# a broken feature
# --------------------------------------------------------------------------


def test_a_single_analyst_stops_at_the_source_budget() -> None:
    """The bound that stops a single source is the budget, not the share.

    ADR-0005 has the measurements: the share cap held one source to 35% of the
    window, which on a 500-entry window is ~175 observations where 15-25 move the
    verdict. The budget binds at exactly its value whatever the team size.
    """
    with client(
        adaptive_learning_enabled=True,
        auth_mode="local",
        bootstrap_admin_token="test-admin-token",
    ) as api:
        headers = {"Authorization": "Bearer test-admin-token"}
        for _ in range(40):
            event = ingest_authenticated(api, headers)
            api.post(
                "/api/v1/feedback",
                json={"target_type": "event", "target_id": event["id"], "label": "true_positive"},
                headers=headers,
            )
        body = api.get("/api/v1/learning/status", headers=headers).json()

    # The per-source budget is what stops it now, and it binds exactly.
    assert body["updates"] == 20
    assert body["max_source_updates"] == 20
    # And the operator can see why, rather than watching it stall in silence.
    assert body["max_source_share"] == pytest.approx(0.35)
    assert body["active_sources"] == 1


def test_a_small_team_no_longer_needs_the_share_cap_raised() -> None:
    """The share cap is floored at an even split, so it stops being the blocker.

    Before, a one-analyst deployment had to set the share cap to 1.0 to train at
    all. Now the binding constraint is the per-source budget, which is the bound
    that is actually a security bound.
    """
    with client(
        adaptive_learning_enabled=True,
        auth_mode="local",
        bootstrap_admin_token="test-admin-token",
    ) as api:
        headers = {"Authorization": "Bearer test-admin-token"}
        for _ in range(40):
            event = ingest_authenticated(api, headers)
            api.post(
                "/api/v1/feedback",
                json={"target_type": "event", "target_id": event["id"], "label": "true_positive"},
                headers=headers,
            )
        body = api.get("/api/v1/learning/status", headers=headers).json()

    # The default share cap is untouched, and a single analyst still trains up to
    # the budget rather than stalling at the share cap.
    assert body["max_source_share"] == pytest.approx(0.35)
    assert body["updates"] == 20 == body["max_source_updates"]


def test_raising_the_source_budget_raises_throughput() -> None:
    with client(
        adaptive_learning_enabled=True,
        auth_mode="local",
        bootstrap_admin_token="test-admin-token",
        adaptive_max_source_updates=40,
    ) as api:
        headers = {"Authorization": "Bearer test-admin-token"}
        for _ in range(40):
            event = ingest_authenticated(api, headers)
            api.post(
                "/api/v1/feedback",
                json={"target_type": "event", "target_id": event["id"], "label": "true_positive"},
                headers=headers,
            )
        body = api.get("/api/v1/learning/status", headers=headers).json()

    assert body["updates"] == 40
    assert body["max_source_updates"] == 40


def test_the_guard_bounds_come_from_configuration() -> None:
    with client(
        adaptive_max_source_share=0.6,
        adaptive_window_hours=6,
        adaptive_label_flood_threshold=7,
    ) as api:
        body = api.get("/api/v1/learning/status").json()
    assert body["max_source_share"] == pytest.approx(0.6)
