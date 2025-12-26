from __future__ import annotations

import os
from typing import Any, Iterable, Mapping, MutableMapping, Optional, Set
from uuid import uuid4

from celery import Celery

from .models import ActivityEvent, IdentityContext, PrivilegeChange
from .persistence import AssessmentRepository
from .risk_engine import RiskEngine


def _broker_url() -> str:
    return os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")


def _result_backend() -> str:
    return os.getenv("CELERY_RESULT_BACKEND", _broker_url())


def _mongodb_uri() -> str:
    return os.getenv("MONGODB_URI", "mongodb://mongo:27017/")


def _mongodb_database() -> str:
    return os.getenv("MONGODB_DATABASE", "suspicious_activity")


celery_app = Celery("suspicious_activity_detector", broker=_broker_url(), backend=_result_backend())
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

_ENGINE: Optional[RiskEngine] = None
_REPOSITORY: Optional[AssessmentRepository] = None


def _get_engine() -> RiskEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = RiskEngine()
    return _ENGINE


def _get_repository() -> AssessmentRepository:
    global _REPOSITORY
    if _REPOSITORY is None:
        _REPOSITORY = AssessmentRepository(uri=_mongodb_uri(), database=_mongodb_database())
    return _REPOSITORY


def _to_identity(payload: Mapping[str, Any]) -> IdentityContext:
    return IdentityContext(
        user_id=str(payload.get("user_id")),
        device_id=str(payload.get("device_id")),
        ip=str(payload.get("ip")),
        geo=str(payload.get("geo")),
        user_agent=str(payload.get("user_agent")),
        session_id=payload.get("session_id"),
        roles=set(payload.get("roles", [])),
        privileges=set(payload.get("privileges", [])),
        timestamp=payload.get("timestamp"),
    )


def _to_activity(payload: Mapping[str, Any]) -> ActivityEvent:
    return ActivityEvent(
        timestamp=payload.get("timestamp"),
        endpoint=str(payload.get("endpoint")),
        method=str(payload.get("method")),
        status_code=int(payload.get("status_code")),
        latency_ms=float(payload.get("latency_ms")),
        bytes_in=int(payload.get("bytes_in")),
        bytes_out=int(payload.get("bytes_out")),
        service=str(payload.get("service")),
        trace_id=str(payload.get("trace_id")),
        metadata=payload.get("metadata", {}),
    )


def _to_privilege_change(payload: Optional[Mapping[str, Any]]) -> Optional[PrivilegeChange]:
    if payload is None:
        return None
    return PrivilegeChange(
        previous_roles=_as_iterable(payload.get("previous_roles", [])),
        new_roles=_as_iterable(payload.get("new_roles", [])),
        previous_privileges=_as_iterable(payload.get("previous_privileges", [])),
        new_privileges=_as_iterable(payload.get("new_privileges", [])),
        timestamp=payload.get("timestamp"),
    )


def _as_iterable(value: Any) -> Iterable[str]:
    if isinstance(value, Set):
        return value
    if isinstance(value, (list, tuple, set)):
        return value
    return [value] if value is not None else []


@celery_app.task(name="suspicious_activity_detector.process_assessment")
def process_assessment(
    task_id: str,
    identity: Mapping[str, Any],
    event: Mapping[str, Any],
    privilege_change: Optional[Mapping[str, Any]] = None,
) -> MutableMapping[str, Any]:
    engine = _get_engine()
    repo = _get_repository()
    assessment = engine.assess_event(
        _to_identity(identity),
        _to_activity(event),
        _to_privilege_change(privilege_change),
    )
    repo.save_assessment(task_id, identity, event, assessment, privilege_change)
    return repo.serialize_assessment(assessment)


def enqueue_assessment(
    identity: Mapping[str, Any],
    event: Mapping[str, Any],
    privilege_change: Optional[Mapping[str, Any]] = None,
) -> str:
    task_id = str(uuid4())
    process_assessment.apply_async(args=[task_id, identity, event, privilege_change], task_id=task_id)
    return task_id
