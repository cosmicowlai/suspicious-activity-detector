from datetime import datetime, timedelta

from suspicious_activity_detector import (
    ActivityEvent,
    EngineConfig,
    IdentityContext,
    PrivilegeChange,
    RiskEngine,
)


def build_identity(now: datetime, user: str, device: str, ip: str, geo: str, session: str | None = None):
    return IdentityContext(
        user_id=user,
        device_id=device,
        ip=ip,
        geo=geo,
        user_agent="Mozilla/5.0",
        session_id=session,
        roles={"user"},
        privileges={"read"},
        timestamp=now,
    )


def main() -> None:
    now = datetime.utcnow()
    config = EngineConfig()
    engine = RiskEngine(config)

    benign_sequence = [
        ActivityEvent(now - timedelta(minutes=10), "/profile", "GET", 200, 120, 200, 400, "profile", "trace-1"),
        ActivityEvent(now - timedelta(minutes=8), "/orders", "GET", 200, 140, 0, 1024, "orders", "trace-2"),
        ActivityEvent(now - timedelta(minutes=6), "/orders", "GET", 200, 130, 0, 2048, "orders", "trace-2"),
    ]

    engine.bootstrap_model([benign_sequence])

    privilege_change = PrivilegeChange(
        previous_roles={"user"},
        new_roles={"user", "admin"},
        previous_privileges={"read"},
        new_privileges={"read", "write", "export"},
        timestamp=now,
    )

    risky_event = ActivityEvent(
        timestamp=now,
        endpoint="/admin/export",
        method="POST",
        status_code=200,
        latency_ms=600,
        bytes_in=512,
        bytes_out=5_000_000,
        service="reporting",
        trace_id="trace-attack",
    )
    identity = build_identity(now, user="alice", device="device-x", ip="10.0.0.10", geo="US", session="s-1")

    assessment = engine.assess_event(identity, risky_event, privilege_change=privilege_change)

    print("Total risk score:", assessment.total_score)
    for signal in assessment.signals:
        print(f"- {signal.name}: {signal.score:.2f} :: {signal.detail}")
    print("Proposed action:", assessment.action)
    print("Account frozen:", assessment.account_frozen)
    print("Session invalidated:", assessment.session_invalidated)


if __name__ == "__main__":
    main()
