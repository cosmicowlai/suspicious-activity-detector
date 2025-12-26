from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Set

from .models import AccountState, ActivityEvent, PrivilegeChange, RiskSignal, TimingStats


class TimingProfiler:
    def __init__(self, sigma_threshold: float):
        self.stats: Dict[str, TimingStats] = defaultdict(TimingStats)
        self.sigma_threshold = sigma_threshold

    def assess(self, event: ActivityEvent) -> RiskSignal | None:
        stats = self.stats[event.endpoint]
        stats.update(event.latency_ms)
        if stats.count < 5:
            return None
        deviation = abs(event.latency_ms - stats.mean)
        if deviation > self.sigma_threshold * (stats.stddev + 1e-6):
            return RiskSignal(
                name="timing_anomaly",
                score=15.0,
                detail=f"Latency {event.latency_ms:.2f}ms diverges from mean {stats.mean:.2f}ms",
            )
        return None


class PrivilegeMonitor:
    def __init__(self, drift_threshold: int):
        self.drift_threshold = drift_threshold

    def assess(self, account: AccountState, change: PrivilegeChange | None) -> List[RiskSignal]:
        signals: List[RiskSignal] = []
        if change:
            previous = set(change.previous_privileges)
            new = set(change.new_privileges)
            escalated = new - previous
            if escalated:
                signals.append(
                    RiskSignal(
                        name="privilege_escalation",
                        score=35.0,
                        detail=f"Privileges added: {sorted(escalated)}",
                    )
                )
            account.privilege_history.append(change)
        if len(account.privilege_history) >= self.drift_threshold:
            recent = account.privilege_history[-self.drift_threshold :]
            union_prev: Set[str] = set()
            union_new: Set[str] = set()
            for item in recent:
                union_prev.update(item.previous_privileges)
                union_new.update(item.new_privileges)
            drifted = union_new - union_prev
            if drifted:
                signals.append(
                    RiskSignal(
                        name="privilege_drift",
                        score=20.0,
                        detail=f"Privileges drifted upward: {sorted(drifted)}",
                    )
                )
        return signals


class PivotTracker:
    def __init__(self, depth_threshold: int):
        self.depth_threshold = depth_threshold
        self.traces: Dict[str, List[str]] = defaultdict(list)

    def assess(self, event: ActivityEvent) -> RiskSignal | None:
        trace = self.traces[event.trace_id]
        trace.append(event.service)
        unique_services = list(dict.fromkeys(trace))
        if len(unique_services) >= self.depth_threshold:
            return RiskSignal(
                name="microservice_pivot",
                score=18.0,
                detail=f"Trace {event.trace_id} pivoted across {len(unique_services)} services",
            )
        return None


class GraphModel:
    def __init__(self):
        self.user_to_ips: Dict[str, Set[str]] = defaultdict(set)
        self.user_to_devices: Dict[str, Set[str]] = defaultdict(set)
        self.ip_to_users: Dict[str, Set[str]] = defaultdict(set)

    def assess(self, user_id: str, ip: str, device_id: str) -> RiskSignal | None:
        seen_ip = ip in self.user_to_ips[user_id]
        seen_device = device_id in self.user_to_devices[user_id]

        self.user_to_ips[user_id].add(ip)
        self.user_to_devices[user_id].add(device_id)
        self.ip_to_users[ip].add(user_id)

        if not seen_ip and len(self.ip_to_users[ip]) > 3:
            return RiskSignal(
                name="shared_ip_risk",
                score=22.0,
                detail=f"IP {ip} shared across {len(self.ip_to_users[ip])} accounts",
            )

        if not seen_device and len(self.user_to_devices[user_id]) > 4:
            return RiskSignal(
                name="device_sprawl",
                score=16.0,
                detail=f"User {user_id} is now active on {len(self.user_to_devices[user_id])} devices",
            )
        return None
