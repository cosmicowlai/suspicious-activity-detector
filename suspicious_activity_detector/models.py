from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Set


@dataclass(slots=True)
class IdentityContext:
    user_id: str
    device_id: str
    ip: str
    geo: str
    user_agent: str
    session_id: Optional[str]
    roles: Set[str]
    privileges: Set[str]
    timestamp: datetime


@dataclass(slots=True)
class ActivityEvent:
    timestamp: datetime
    endpoint: str
    method: str
    status_code: int
    latency_ms: float
    bytes_in: int
    bytes_out: int
    service: str
    trace_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def risk_surface(self) -> float:
        admin_like = ["/admin", "/export", "/internal", "/elevate"]
        admin_score = 1.0 if any(self.endpoint.startswith(p) for p in admin_like) else 0.0
        volume_score = min(self.bytes_out / 1_000_000, 5.0)
        return admin_score + volume_score


@dataclass(slots=True)
class PrivilegeChange:
    previous_roles: Iterable[str]
    new_roles: Iterable[str]
    previous_privileges: Iterable[str]
    new_privileges: Iterable[str]
    timestamp: datetime


@dataclass(slots=True)
class RiskSignal:
    name: str
    score: float
    detail: str


@dataclass(slots=True)
class RiskAssessment:
    total_score: float
    signals: List[RiskSignal]
    action: str
    account_frozen: bool = False
    session_invalidated: bool = False


@dataclass(slots=True)
class TimingStats:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def stddev(self) -> float:
        return self.variance ** 0.5


@dataclass(slots=True)
class SessionState:
    session_id: str
    device_id: str
    created_at: datetime
    last_seen: datetime
    ip: str


@dataclass(slots=True)
class AccountState:
    user_id: str
    sessions: MutableMapping[str, SessionState] = field(default_factory=dict)
    frozen: bool = False
    privilege_history: List[PrivilegeChange] = field(default_factory=list)
    last_fingerprint: Optional[str] = None

    def active_devices(self) -> Set[str]:
        return {session.device_id for session in self.sessions.values()}

    def update_session(self, session: SessionState) -> None:
        self.sessions[session.session_id] = session
        self.last_fingerprint = session.device_id

    def expire_session(self, session_id: str) -> None:
        self.sessions.pop(session_id, None)
