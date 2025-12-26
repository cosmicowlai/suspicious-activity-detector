from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .models import ActivityEvent, IdentityContext, PrivilegeChange, RiskAssessment, RiskSignal
from .risk_engine import RiskEngine


class IdentityPayload(BaseModel):
    user_id: str
    device_id: str
    ip: str
    geo: str
    user_agent: str
    session_id: Optional[str] = None
    roles: Set[str]
    privileges: Set[str]
    timestamp: datetime


class ActivityPayload(BaseModel):
    timestamp: datetime
    endpoint: str
    method: str
    status_code: int
    latency_ms: float
    bytes_in: int
    bytes_out: int
    service: str
    trace_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PrivilegeChangePayload(BaseModel):
    previous_roles: Set[str]
    new_roles: Set[str]
    previous_privileges: Set[str]
    new_privileges: Set[str]
    timestamp: datetime


class AssessRequest(BaseModel):
    identity: IdentityPayload
    event: ActivityPayload
    privilege_change: Optional[PrivilegeChangePayload] = None


class RiskSignalResponse(BaseModel):
    name: str
    score: float
    detail: str


class AssessmentResponse(BaseModel):
    total_score: float
    action: str
    signals: List[RiskSignalResponse]
    account_frozen: bool
    session_invalidated: bool


class SummaryResponse(BaseModel):
    user_id: str
    frozen: bool
    active_sessions: List[str]
    behavior: Dict[str, float]
    recent_sequence: List[str]


def _to_identity(payload: IdentityPayload) -> IdentityContext:
    return IdentityContext(**payload.model_dump())


def _to_activity(payload: ActivityPayload) -> ActivityEvent:
    return ActivityEvent(**payload.model_dump())


def _to_privilege_change(payload: PrivilegeChangePayload | None) -> PrivilegeChange | None:
    if payload is None:
        return None
    return PrivilegeChange(**payload.model_dump())


def _serialize_signal(signal: RiskSignal) -> RiskSignalResponse:
    return RiskSignalResponse(name=signal.name, score=signal.score, detail=signal.detail)


def _serialize_assessment(assessment: RiskAssessment) -> AssessmentResponse:
    return AssessmentResponse(
        total_score=assessment.total_score,
        action=assessment.action,
        signals=[_serialize_signal(signal) for signal in assessment.signals],
        account_frozen=assessment.account_frozen,
        session_invalidated=assessment.session_invalidated,
    )


def _serialize_summary(user_id: str, summary: Dict[str, object]) -> SummaryResponse:
    return SummaryResponse(
        user_id=user_id,
        frozen=bool(summary.get("frozen")),
        active_sessions=[str(session) for session in summary.get("active_sessions", [])],
        behavior={str(k): float(v) for k, v in summary.get("behavior", {}).items()},
        recent_sequence=[str(item) for item in summary.get("recent_sequence", [])],
    )


def create_app(engine: RiskEngine | None = None) -> FastAPI:
    app = FastAPI(title="Suspicious Activity Detector API", version="1.0.0")
    app.state.engine = engine or RiskEngine()

    @app.get("/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @app.post("/assess", response_model=AssessmentResponse)
    def assess(request: AssessRequest) -> AssessmentResponse:
        identity = _to_identity(request.identity)
        event = _to_activity(request.event)
        privilege_change = _to_privilege_change(request.privilege_change)
        assessment = app.state.engine.assess_event(identity, event, privilege_change)
        return _serialize_assessment(assessment)

    @app.get("/accounts/{user_id}/summary", response_model=SummaryResponse)
    def account_summary(user_id: str) -> SummaryResponse:
        summary = app.state.engine.summary(user_id)
        return _serialize_summary(user_id, summary)

    @app.post("/accounts/{user_id}/freeze", response_model=SummaryResponse)
    def freeze_account(user_id: str) -> SummaryResponse:
        app.state.engine.freeze_account(user_id)
        summary = app.state.engine.summary(user_id)
        return _serialize_summary(user_id, summary)

    @app.post("/accounts/{user_id}/reset-sessions", response_model=SummaryResponse)
    def reset_sessions(user_id: str) -> SummaryResponse:
        app.state.engine.reset_sessions(user_id)
        summary = app.state.engine.summary(user_id)
        return _serialize_summary(user_id, summary)

    return app


app = create_app()
