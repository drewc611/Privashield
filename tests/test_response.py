from fastapi.testclient import TestClient

from privashield_api.config import Settings
from privashield_api.main import create_app


def client() -> TestClient:
    return TestClient(
        create_app(
            Settings(
                database_enabled=False,
                nats_enabled=False,
                ollama_enabled=False,
                audit_path=None,
                environment="test",
            )
        )
    )


def test_response_action_requires_approval_before_simulation() -> None:
    with client() as api:
        created = api.post(
            "/api/v1/response/actions",
            json={
                "action_type": "block_ip",
                "target": "198.51.100.44",
                "reason": "Synthetic malicious source",
            },
        )
        assert created.status_code == 201
        action_id = created.json()["id"]
        assert created.json()["status"] == "pending"
        assert created.json()["enforced"] is False

        premature = api.post(f"/api/v1/response/actions/{action_id}/simulate")
        assert premature.status_code == 409

        approved = api.post(
            f"/api/v1/response/actions/{action_id}/approve",
            json={"approved_by": "security-admin"},
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"

        simulated = api.post(f"/api/v1/response/actions/{action_id}/simulate")
        assert simulated.status_code == 200
        assert simulated.json()["status"] == "simulated"
        assert simulated.json()["enforced"] is False


def test_response_capabilities_never_claim_privileged_execution() -> None:
    with client() as api:
        response = api.get("/api/v1/response/capabilities")
        assert response.status_code == 200
        assert response.json()["simulation"] is True
        assert response.json()["privileged_execution"] is False
        assert "block_ip" in response.json()["supported_actions"]
