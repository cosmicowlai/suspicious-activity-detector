from datetime import datetime, timedelta

from suspicious_activity_detector import (
    ActivityEvent,
    EngineConfig,
    IdentityContext,
    PrivilegeChange,
    RiskEngine,
)


def make_identity(now: datetime, session: str = "s-1"):
    return IdentityContext(
        user_id="user-1",
        device_id="device-1",
        ip="192.168.1.10",
        geo="US",
        user_agent="Mozilla/5.0",
        session_id=session,
        roles={"user"},
        privileges={"read"},
        timestamp=now,
    )


def make_event(now: datetime, endpoint: str = "/profile", service: str = "profile", trace: str = "t-1"):
    return ActivityEvent(
        timestamp=now,
        endpoint=endpoint,
        method="GET",
        status_code=200,
        latency_ms=120,
        bytes_in=100,
        bytes_out=512,
        service=service,
        trace_id=trace,
    )


def test_privilege_escalation_signal():
    engine = RiskEngine(EngineConfig(high_risk_threshold=50, medium_risk_threshold=25))
    now = datetime.utcnow()
    identity = make_identity(now)
    event = make_event(now, endpoint="/admin/export")
    change = PrivilegeChange(
        previous_roles={"user"},
        new_roles={"user", "admin"},
        previous_privileges={"read"},
        new_privileges={"read", "write"},
        timestamp=now,
    )
    assessment = engine.assess_event(identity, event, privilege_change=change)
    assert any(signal.name == "privilege_escalation" for signal in assessment.signals)
    assert assessment.action in {"freeze_account", "force_logout", "monitor"}


def test_sequence_and_behavior_anomaly():
    engine = RiskEngine(EngineConfig(medium_risk_threshold=15))
    now = datetime.utcnow()
    identity = make_identity(now)

    # establish baseline sequence
    for offset in range(3):
        engine.assess_event(identity, make_event(now + timedelta(minutes=offset), endpoint="/profile"))

    unusual = make_event(now + timedelta(minutes=10), endpoint="/admin/export")
    assessment = engine.assess_event(identity, unusual)
    names = {signal.name for signal in assessment.signals}
    assert {"api_sequence_anomaly"}.issubset(names)


def test_multi_actor_detection():
    engine = RiskEngine(EngineConfig(multi_actor_window=timedelta(hours=1)))
    now = datetime.utcnow()
    identity = make_identity(now, session="s-1")
    engine.assess_event(identity, make_event(now))

    # new device shortly after triggers multi-actor risk signal
    identity2 = IdentityContext(
        user_id="user-1",
        device_id="device-2",
        ip="10.0.0.5",
        geo="CA",
        user_agent="Mozilla/5.0",
        session_id="s-2",
        roles={"user"},
        privileges={"read"},
        timestamp=now + timedelta(minutes=5),
    )
    assessment = engine.assess_event(identity2, make_event(now + timedelta(minutes=5), endpoint="/orders"))
    assert any(signal.name == "multi_actor_detection" for signal in assessment.signals)
