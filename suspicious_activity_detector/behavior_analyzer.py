from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, List

from .models import ActivityEvent, RiskSignal


class BehaviorProfile:
    def __init__(self, window: timedelta):
        self.window = window
        self.events: Deque[ActivityEvent] = deque()
        self.endpoint_counter: Counter[str] = Counter()

    def observe(self, event: ActivityEvent) -> None:
        self.events.append(event)
        self.endpoint_counter[event.endpoint] += 1
        self._trim(event.timestamp)

    def _trim(self, now: datetime) -> None:
        while self.events and now - self.events[0].timestamp > self.window:
            old = self.events.popleft()
            self.endpoint_counter[old.endpoint] -= 1
            if self.endpoint_counter[old.endpoint] <= 0:
                del self.endpoint_counter[old.endpoint]

    def request_rate(self) -> float:
        if not self.events:
            return 0.0
        window_seconds = max((self.events[-1].timestamp - self.events[0].timestamp).total_seconds(), 1.0)
        return len(self.events) / window_seconds

    def endpoint_skew(self, endpoint: str) -> float:
        total = sum(self.endpoint_counter.values()) or 1
        return self.endpoint_counter.get(endpoint, 0) / total


class BehaviorAnomalyDetector:
    def __init__(self, window: timedelta):
        self.window = window
        self.profiles: Dict[str, BehaviorProfile] = {}

    def assess(self, user_id: str, event: ActivityEvent) -> RiskSignal | None:
        profile = self.profiles.setdefault(user_id, BehaviorProfile(self.window))
        request_rate_before = profile.request_rate()
        endpoint_ratio_before = profile.endpoint_skew(event.endpoint)

        profile.observe(event)
        request_rate_after = profile.request_rate()
        endpoint_ratio_after = profile.endpoint_skew(event.endpoint)

        surge = (request_rate_after - request_rate_before) / (request_rate_before + 0.01)
        endpoint_spike = (endpoint_ratio_after - endpoint_ratio_before)

        if surge > 2.0:
            return RiskSignal(
                name="behavior_rate_anomaly",
                score=min(20.0 * surge, 40.0),
                detail=f"Request rate surged by {surge:.2f}x for user {user_id}",
            )

        if endpoint_spike > 0.3 and endpoint_ratio_after > 0.5:
            return RiskSignal(
                name="behavior_endpoint_anomaly",
                score=25.0,
                detail=f"Endpoint {event.endpoint} suddenly dominates traffic for user {user_id}",
            )

        return None

    def volume_summary(self, user_id: str) -> Dict[str, float]:
        profile = self.profiles.get(user_id)
        if not profile:
            return {"request_rate": 0.0}
        return {"request_rate": profile.request_rate()}
