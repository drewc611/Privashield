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
