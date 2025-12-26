from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, List, Sequence

from .models import ActivityEvent, RiskSignal


@dataclass(slots=True)
class _FeatureStats:
    count: int = 0
    mean: List[float] = field(default_factory=list)
    m2: List[float] = field(default_factory=list)

    def update(self, vector: List[float]) -> None:
        if not self.mean:
            self.mean = [0.0 for _ in vector]
            self.m2 = [0.0 for _ in vector]
        self.count += 1
        for i, value in enumerate(vector):
            delta = value - self.mean[i]
            self.mean[i] += delta / self.count
            delta2 = value - self.mean[i]
            self.m2[i] += delta * delta2

    def stddev(self) -> List[float]:
        if self.count < 2:
            return [1.0 for _ in self.mean]
        return [(m2 / (self.count - 1)) ** 0.5 or 1.0 for m2 in self.m2]


class AttackSequencePredictor:
    """Lightweight statistical detector over engineered features."""

    def __init__(self, contamination: float, score_multiplier: float):
        self.score_multiplier = score_multiplier
        self.is_trained = False
        self.stats = _FeatureStats()
        self.threshold = max(contamination, 0.05) * 6  # heuristic z-score budget

    def fit(self, sequences: Iterable[Sequence[ActivityEvent]]) -> None:
        for seq in sequences:
            self.stats.update(self._featurize(seq))
        self.is_trained = self.stats.count > 0

    def update_baseline(self, sequence: Sequence[ActivityEvent]) -> None:
        self.stats.update(self._featurize(sequence))
        self.is_trained = self.stats.count > 0

    def score(self, sequence: Sequence[ActivityEvent]) -> RiskSignal | None:
        if not self.is_trained:
            return None
        vector = self._featurize(sequence)
        stds = self.stats.stddev()
        z_scores = [abs(v - mean) / std for v, mean, std in zip(vector, self.stats.mean, stds)]
        anomaly_budget = sum(max(z - self.threshold, 0.0) for z in z_scores)
        if anomaly_budget <= 0:
            return None
        score = min(anomaly_budget * self.score_multiplier, 30.0)
        return RiskSignal(
            name="ml_attack_prediction",
            score=score,
            detail="Statistical model flags attack-like sequence",
        )

    def _featurize(self, sequence: Sequence[ActivityEvent]) -> List[float]:
        admin_hits = sum(1 for event in sequence if "/admin" in event.endpoint or "export" in event.endpoint)
        status_errors = sum(1 for event in sequence if event.status_code >= 400)
        services = Counter(event.service for event in sequence)
        unique_services = len(services)
        avg_latency = sum(event.latency_ms for event in sequence) / (len(sequence) or 1)
        max_burst = max((event.bytes_out for event in sequence), default=0)
        return [
            len(sequence),
            admin_hits,
            status_errors,
            unique_services,
            avg_latency,
            max_burst,
        ]
