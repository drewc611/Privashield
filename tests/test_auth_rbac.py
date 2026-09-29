from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from starlette.websockets import WebSocketDisconnect

from privashield_api.config import Settings
from privashield_api.main import create_app

BOOTSTRAP = "test-bootstrap-admin-token-with-high-entropy-0123456789"


def client(
    *,
    auth_mode: Literal["disabled", "local"] = "local",
    bootstrap: str | None = BOOTSTRAP,
) -> TestClient:
    return TestClient(
        create_app(
            Settings(
                database_enabled=False,
                nats_enabled=False,
                ollama_enabled=False,
                audit_path=None,
                environment="test",
                auth_mode=auth_mode,
                bootstrap_admin_token=SecretStr(bootstrap) if bootstrap else None,
            )
        )
    )


def headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def issue_principal(
    api: TestClient,
    *,
    name: str,
    role: str,
    admin_token: str = BOOTSTRAP,
) -> tuple[str, UUID]:
    response = api.post(
        "/api/v1/principals",
        headers=headers(admin_token),
        json={"name": name, "role": role},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["token"].startswith("psh_")
    assert body["token_display"] == "shown-once"
    assert "token_digest" not in body["principal"]
    return body["token"], UUID(body["principal"]["id"])


def test_auth_disabled_preserves_loopback_development_mode() -> None:
    with client(auth_mode="disabled", bootstrap=None) as api:
        response = api.get("/api/v1/auth/me")
        assert response.status_code == 200
        body = response.json()
        assert body["role"] == "administrator"
        assert body["credential_verified"] is False
        assert body["name"] == "local-development-unverified"

        assert api.get("/api/v1/events").status_code == 200


def test_local_auth_requires_credentials_except_health() -> None:
    with client() as api:
        assert api.get("/api/v1/health").status_code == 200
        assert api.get("/api/v1/system/status").status_code == 401
        assert api.get("/api/v1/system/status", headers=headers("invalid-token")).status_code == 401

        response = api.get("/api/v1/auth/me", headers=headers(BOOTSTRAP))
        assert response.status_code == 200
        body = response.json()
        assert body["name"] == "bootstrap-administrator"
        assert body["role"] == "administrator"
        assert body["credential_verified"] is True
        assert body["bootstrap"] is True


def test_principal_tokens_are_one_time_and_digest_is_never_returned() -> None:
    with client() as api:
        token, principal_id = issue_principal(api, name="viewer-one", role="viewer")
        assert len(token) > 32

        principals = api.get("/api/v1/principals", headers=headers(BOOTSTRAP))
        assert principals.status_code == 200
        principal = next(item for item in principals.json() if item["id"] == str(principal_id))
        assert "token" not in principal
        assert "token_digest" not in principal
        assert token not in str(principals.json())
        assert principal["token_prefix"] == token[:12]


def test_role_matrix_is_enforced_server_side() -> None:
    with client() as api:
        viewer_token, _ = issue_principal(api, name="viewer", role="viewer")
        analyst_token, _ = issue_principal(api, name="analyst", role="analyst")
        operator_token, _ = issue_principal(api, name="operator", role="operator")
        auditor_token, _ = issue_principal(api, name="auditor", role="auditor")

        assert api.get("/api/v1/events", headers=headers(viewer_token)).status_code == 200
        assert (
            api.patch(
                "/api/v1/firewall/config",
                headers=headers(viewer_token),
                json={"mode": "simulate", "threshold": 0.9},
            ).status_code
            == 403
        )
        assert api.get("/api/v1/audit/verify", headers=headers(viewer_token)).status_code == 403

        assert (
            api.post(
                "/api/v1/firewall/evaluate",
                headers=headers(analyst_token),
                json={"risk_score": 0.9, "reason": "role boundary test"},
            ).status_code
            == 403
        )

        operator_update = api.patch(
            "/api/v1/firewall/config",
            headers=headers(operator_token),
            json={"mode": "simulate", "threshold": 0.9},
        )
        assert operator_update.status_code == 200
        assert api.get("/api/v1/audit/verify", headers=headers(operator_token)).status_code == 403

        assert api.get("/api/v1/audit/verify", headers=headers(auditor_token)).status_code == 200
        assert (
            api.patch(
                "/api/v1/firewall/config",
                headers=headers(auditor_token),
                json={"mode": "observe", "threshold": 0.8},
            ).status_code
            == 403
        )

        assert api.get("/api/v1/principals", headers=headers(operator_token)).status_code == 403
        assert api.get("/api/v1/principals", headers=headers(BOOTSTRAP)).status_code == 200


def test_token_rotation_and_disablement_take_effect_immediately() -> None:
    with client() as api:
        viewer_token, viewer_id = issue_principal(api, name="rotating-viewer", role="viewer")
        assert api.get("/api/v1/events", headers=headers(viewer_token)).status_code == 200

        rotated = api.post(
            f"/api/v1/principals/{viewer_id}/rotate",
            headers=headers(BOOTSTRAP),
            json={"reason": "scheduled rotation"},
        )
        assert rotated.status_code == 200
        new_token = rotated.json()["token"]
        assert new_token != viewer_token
        assert api.get("/api/v1/events", headers=headers(viewer_token)).status_code == 401
        assert api.get("/api/v1/events", headers=headers(new_token)).status_code == 200

        disabled = api.post(
            f"/api/v1/principals/{viewer_id}/disable",
            headers=headers(BOOTSTRAP),
            json={"reason": "offboarding"},
        )
        assert disabled.status_code == 200
        assert disabled.json()["enabled"] is False
        assert api.get("/api/v1/events", headers=headers(new_token)).status_code == 401


def test_administrator_cannot_disable_own_active_principal() -> None:
    with client() as api:
        admin_token, admin_id = issue_principal(api, name="durable-admin", role="administrator")
        response = api.post(
            f"/api/v1/principals/{admin_id}/disable",
            headers=headers(admin_token),
            json={"reason": "accidental self lockout"},
        )
        assert response.status_code == 409
        assert "cannot disable" in response.json()["detail"]
        assert api.get("/api/v1/auth/me", headers=headers(admin_token)).status_code == 200


def test_verified_principal_overrides_spoofed_response_actor_fields() -> None:
    with client() as api:
        requester_token, requester_id = issue_principal(api, name="operator-one", role="operator")
        approver_token, approver_id = issue_principal(api, name="operator-two", role="operator")

        created = api.post(
            "/api/v1/response/actions",
            headers=headers(requester_token),
            json={
                "action_type": "block_ip",
                "target": "198.51.100.44",
                "reason": "verified attribution test",
            },
        )
        assert created.status_code == 201
        body = created.json()
        assert body["requested_by"] == f"operator-one<{requester_id}>"
        action_id = body["id"]

        approved = api.post(
            f"/api/v1/response/actions/{action_id}/approve",
            headers=headers(approver_token),
            json={"approved_by": "spoofed-actor-name"},
        )
        assert approved.status_code == 200
        assert approved.json()["approved_by"] == f"operator-two<{approver_id}>"

        audit = api.get("/api/v1/audit?limit=50", headers=headers(BOOTSTRAP))
        assert audit.status_code == 200
        actors = {entry["actor"] for entry in audit.json()}
        assert f"operator-one<{requester_id}>" in actors
        assert f"operator-two<{approver_id}>" in actors
        assert "spoofed-actor-name" not in actors


def test_authenticated_websocket_stream_accepts_token_without_query_secret() -> None:
    with client() as api:
        viewer_token, _ = issue_principal(api, name="stream-viewer", role="viewer")

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with api.websocket_connect("/api/v1/ws/events"):
                pass
        assert exc_info.value.code == 4401

        with api.websocket_connect(
            "/api/v1/ws/events",
            subprotocols=["privashield", f"privashield.bearer.{viewer_token}"],
        ) as websocket:
            assert websocket.accepted_subprotocol == "privashield"
            event = {
                "timestamp": datetime.now(UTC).isoformat(),
                "source": "system",
                "event_type": "rbac_stream_test",
                "severity": "info",
                "summary": "Authenticated WebSocket test event",
            }
            posted = api.post(
                "/api/v1/events/ingest",
                headers=headers(BOOTSTRAP),
                json=event,
            )
            assert posted.status_code == 201
            message = websocket.receive_json()
            assert message["type"] == "security.event"
            assert message["data"]["event_type"] == "rbac_stream_test"
