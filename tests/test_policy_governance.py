from __future__ import annotations

from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from privashield_api.config import Settings
from privashield_api.main import create_app
from privashield_api.policy_models import PolicyDocument
from privashield_api.policy_signing import sign_policy, verify_policy
from privashield_api.response_models import ResponseActionType

SIGNING_KEY = b"test-only-policy-signing-key-with-sufficient-entropy"
KEY_ID = "test-key-v1"


def client(*, configured: bool = True) -> TestClient:
    return TestClient(
        create_app(
            Settings(
                database_enabled=False,
                nats_enabled=False,
                ollama_enabled=False,
                audit_path=None,
                environment="test",
                policy_signing_key=SIGNING_KEY.decode() if configured else None,
                policy_signing_key_id=KEY_ID,
            )
        )
    )


def document(name: str = "Default response simulation policy") -> PolicyDocument:
    return PolicyDocument(
        name=name,
        description="Govern approved response simulations without privileged execution.",
        allowed_actions=[ResponseActionType.BLOCK_IP, ResponseActionType.QUARANTINE_FILE],
        minimum_risk_score=0.85,
        require_human_approval=True,
        mode="simulate",
        privileged_execution=False,
    )


def signed(policy_id: UUID, version: int, *, name: str | None = None, key_id: str = KEY_ID):
    return sign_policy(
        policy_id=policy_id,
        version=version,
        document=document(name or f"Policy revision {version}"),
        key_id=key_id,
        signing_key=SIGNING_KEY,
    )


def register(api: TestClient, envelope, created_by: str = "author@example.test"):
    return api.post(
        "/api/v1/policies/revisions",
        json={
            "envelope": envelope.model_dump(mode="json"),
            "created_by": created_by,
        },
    )


def test_policy_signature_is_deterministic_and_tamper_evident() -> None:
    policy_id = uuid4()
    first = signed(policy_id, 1)
    second = signed(policy_id, 1)

    assert first.signature == second.signature
    assert verify_policy(first, SIGNING_KEY) is True

    tampered = first.model_copy(deep=True)
    tampered.document.name = "Tampered policy"
    assert verify_policy(tampered, SIGNING_KEY) is False


def test_policy_capabilities_fail_closed_without_signing_key() -> None:
    with client(configured=False) as api:
        capabilities = api.get("/api/v1/policies/capabilities")
        assert capabilities.status_code == 200
        body = capabilities.json()
        assert body["signing_configured"] is False
        assert body["require_human_approval"] is True
        assert body["privileged_execution"] is False
        assert body["activation_effect"] == "simulation-governance-only"

        policy_id = uuid4()
        response = register(api, signed(policy_id, 1))
        assert response.status_code == 503
        assert "signing is not configured" in response.json()["detail"]


def test_policy_rejects_tampering_key_mismatch_and_non_monotonic_versions() -> None:
    policy_id = uuid4()
    with client() as api:
        valid_v1 = signed(policy_id, 1)

        tampered = valid_v1.model_dump(mode="json")
        tampered["document"]["minimum_risk_score"] = 0.10
        response = api.post(
            "/api/v1/policies/revisions",
            json={"envelope": tampered, "created_by": "author@example.test"},
        )
        assert response.status_code == 422
        assert "signature verification failed" in response.json()["detail"]

        mismatched_key_id = signed(policy_id, 1, key_id="unexpected-key")
        response = register(api, mismatched_key_id)
        assert response.status_code == 422
        assert "does not match configured key_id" in response.json()["detail"]

        response = register(api, valid_v1)
        assert response.status_code == 201
        assert response.json()["status"] == "draft"
        assert response.json()["enforced"] is False

        response = register(api, signed(policy_id, 3))
        assert response.status_code == 409
        assert "next monotonic revision (2)" in response.json()["detail"]


def test_policy_requires_second_operator_and_approval_before_activation() -> None:
    policy_id = uuid4()
    with client() as api:
        response = register(api, signed(policy_id, 1), created_by="author@example.test")
        assert response.status_code == 201

        response = api.post(
            f"/api/v1/policies/{policy_id}/revisions/1/activate",
            json={"activated_by": "operator@example.test"},
        )
        assert response.status_code == 409
        assert "approved before activation" in response.json()["detail"]

        response = api.post(
            f"/api/v1/policies/{policy_id}/revisions/1/approve",
            json={"approved_by": "author@example.test"},
        )
        assert response.status_code == 409
        assert "requires a second operator" in response.json()["detail"]

        response = api.post(
            f"/api/v1/policies/{policy_id}/revisions/1/approve",
            json={"approved_by": "reviewer@example.test"},
        )
        assert response.status_code == 200
        approved = response.json()
        assert approved["status"] == "approved"
        assert approved["approved_by"] == "reviewer@example.test"
        assert approved["signature_valid"] is True
        assert approved["enforced"] is False

        response = api.post(
            f"/api/v1/policies/{policy_id}/revisions/1/activate",
            json={"activated_by": "operator@example.test"},
        )
        assert response.status_code == 200
        active = response.json()
        assert active["status"] == "active"
        assert active["enforced"] is False
        assert active["document"]["privileged_execution"] is False

        # Policy activation governs simulation only; it cannot create or execute response actions.
        response_actions = api.get("/api/v1/response/actions")
        assert response_actions.status_code == 200
        assert response_actions.json() == []


def test_policy_version_history_supersession_and_rollback() -> None:
    policy_id = uuid4()
    with client() as api:
        assert register(api, signed(policy_id, 1)).status_code == 201
        assert (
            api.post(
                f"/api/v1/policies/{policy_id}/revisions/1/approve",
                json={"approved_by": "reviewer-one@example.test"},
            ).status_code
            == 200
        )
        assert (
            api.post(
                f"/api/v1/policies/{policy_id}/revisions/1/activate",
                json={"activated_by": "operator@example.test"},
            ).status_code
            == 200
        )

        assert register(api, signed(policy_id, 2), created_by="author-two@example.test").status_code == 201
        assert (
            api.post(
                f"/api/v1/policies/{policy_id}/revisions/2/approve",
                json={"approved_by": "reviewer-two@example.test"},
            ).status_code
            == 200
        )
        response = api.post(
            f"/api/v1/policies/{policy_id}/revisions/2/activate",
            json={"activated_by": "operator@example.test"},
        )
        assert response.status_code == 200
        assert response.json()["version"] == 2

        versions = api.get(f"/api/v1/policies/{policy_id}/revisions")
        assert versions.status_code == 200
        by_version = {item["version"]: item for item in versions.json()}
        assert by_version[1]["status"] == "superseded"
        assert by_version[2]["status"] == "active"

        rollback = api.post(
            f"/api/v1/policies/{policy_id}/rollback",
            json={"target_version": 1, "actor": "rollback-operator@example.test"},
        )
        assert rollback.status_code == 200
        assert rollback.json()["version"] == 1
        assert rollback.json()["status"] == "active"
        assert rollback.json()["enforced"] is False

        active = api.get(f"/api/v1/policies/{policy_id}/active")
        assert active.status_code == 200
        assert active.json()["version"] == 1

        history = api.get(f"/api/v1/policies/{policy_id}/history")
        assert history.status_code == 200
        event_types = [item["event_type"] for item in history.json()]
        assert event_types == [
            "registered",
            "approved",
            "activated",
            "registered",
            "approved",
            "superseded",
            "activated",
            "superseded",
            "rolled_back",
        ]
        assert all(item["policy_id"] == str(policy_id) for item in history.json())


def test_rollback_cannot_select_unapproved_or_forward_revision() -> None:
    policy_id = uuid4()
    with client() as api:
        assert register(api, signed(policy_id, 1)).status_code == 201
        assert (
            api.post(
                f"/api/v1/policies/{policy_id}/revisions/1/approve",
                json={"approved_by": "reviewer@example.test"},
            ).status_code
            == 200
        )
        assert (
            api.post(
                f"/api/v1/policies/{policy_id}/revisions/1/activate",
                json={"activated_by": "operator@example.test"},
            ).status_code
            == 200
        )
        assert register(api, signed(policy_id, 2), created_by="author-two@example.test").status_code == 201

        response = api.post(
            f"/api/v1/policies/{policy_id}/rollback",
            json={"target_version": 2, "actor": "operator@example.test"},
        )
        assert response.status_code == 409
        assert "earlier policy version" in response.json()["detail"]
