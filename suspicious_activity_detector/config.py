from dataclasses import dataclass
from datetime import timedelta


@dataclass(slots=True)
class EngineConfig:
    """Configuration for the risk engine thresholds and behavior."""

    high_risk_threshold: float = 85.0
    medium_risk_threshold: float = 60.0
    sequence_window: int = 10
    behavior_window: timedelta = timedelta(hours=24)
    timing_sigma_threshold: float = 3.0
    privilege_drift_threshold: int = 3
    multi_actor_window: timedelta = timedelta(hours=6)
    pivot_depth_threshold: int = 4
    attack_prediction_contamination: float = 0.08
    attack_prediction_score_multiplier: float = 100.0

    def evaluate_action(self, risk_score: float) -> str:
        if risk_score >= self.high_risk_threshold:
            return "freeze_account"
        if risk_score >= self.medium_risk_threshold:
            return "force_logout"
        return "monitor"
