from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from .models import ActivityEvent, RiskSignal


class APISequenceModel:
    def __init__(self, window: int = 10):
        self.window = window
        self.transitions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.recent_paths: Dict[str, Deque[str]] = defaultdict(deque)

    def observe(self, user_id: str, event: ActivityEvent) -> None:
        path = self.recent_paths[user_id]
        if path:
            prev = path[-1]
            self.transitions[prev][event.endpoint] += 1
        path.append(event.endpoint)
        if len(path) > self.window:
            path.popleft()

    def score(self, user_id: str, event: ActivityEvent) -> RiskSignal | None:
        path = self.recent_paths[user_id]
        if not path:
            self.observe(user_id, event)
            return None
        prev = path[-1]
        next_counts = self.transitions.get(prev, {})
        total = sum(next_counts.values()) or 1
        probability = next_counts.get(event.endpoint, 0) / total
        self.observe(user_id, event)
        if probability < 0.05 and total >= 2:
            return RiskSignal(
                name="api_sequence_anomaly",
                score=30.0,
                detail=f"Unexpected transition from {prev} to {event.endpoint}",
            )
        return None

    def recent_sequence(self, user_id: str) -> Tuple[str, ...]:
        return tuple(self.recent_paths[user_id])
