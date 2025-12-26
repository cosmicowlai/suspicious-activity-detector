from datetime import datetime

from fastapi.testclient import TestClient

from suspicious_activity_detector import EngineConfig, RiskEngine
from suspicious_activity_detector.api import create_app


def build_assess_payload(now: datetime) -> dict:
    return {
        "identity": {
            "user_id": "user-42",
            "device_id": "device-1",
            "ip": "10.0.0.1",
            "geo": "US",
            "user_agent": "pytest",
            "session_id": "session-1",
            "roles": ["user"],
            "privileges": ["read"],
            "timestamp": now.isoformat(),
        },
        "event": {
            "timestamp": now.isoformat(),
            "endpoint": "/admin/export",
            "method": "POST",
            "status_code": 200,
            "latency_ms": 120,
            "bytes_in": 128,
            "bytes_out": 2048,
            "service": "admin",
            "trace_id": "trace-1",
            "metadata": {"source": "test"},
        },
        "privilege_change": {
            "previous_roles": ["user"],
            "new_roles": ["user", "admin"],
            "previous_privileges": ["read"],
            "new_privileges": ["read", "write"],
            "timestamp": now.isoformat(),
        },
    }


def test_healthcheck():
    client = TestClient(create_app())
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_assess_endpoint_returns_risk_assessment():
    engine = RiskEngine(EngineConfig(medium_risk_threshold=25, high_risk_threshold=50))
    client = TestClient(create_app(engine))
    now = datetime.utcnow()

    response = client.post("/assess", json=build_assess_payload(now))
    assert response.status_code == 200

    body = response.json()
    signal_names = {signal["name"] for signal in body["signals"]}
    assert "privilege_escalation" in signal_names
    assert body["total_score"] > 0
    assert body["action"] in {"monitor", "force_logout", "freeze_account"}


def test_account_controls_and_summary():
    engine = RiskEngine(EngineConfig())
    app = create_app(engine)
    client = TestClient(app)
    now = datetime.utcnow()

    # establish activity to create session state
    payload = build_assess_payload(now)
    client.post("/assess", json=payload)

    freeze_response = client.post("/accounts/user-42/freeze")
    assert freeze_response.status_code == 200
    assert freeze_response.json()["frozen"] is True

    summary_response = client.get("/accounts/user-42/summary")
    assert summary_response.status_code == 200
    assert "recent_sequence" in summary_response.json()

    reset_response = client.post("/accounts/user-42/reset-sessions")
    assert reset_response.status_code == 200
    assert reset_response.json()["active_sessions"] == []
