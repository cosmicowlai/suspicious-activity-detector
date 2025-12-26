from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Deque, Dict, List
from collections import deque

from .attack_predictor import AttackSequencePredictor
from .behavior_analyzer import BehaviorAnomalyDetector
from .config import EngineConfig
from .fingerprinting import IdentityFingerprinter
from .models import (
    AccountState,
    ActivityEvent,
    IdentityContext,
    PrivilegeChange,
    RiskAssessment,
    RiskSignal,
    SessionState,
)
from .security_monitors import GraphModel, PivotTracker, PrivilegeMonitor, TimingProfiler
from .sequence_model import APISequenceModel


class RiskEngine:
    def __init__(self, config: EngineConfig | None = None):
        self.config = config or EngineConfig()
        self.accounts: Dict[str, AccountState] = {}
        self.behavior = BehaviorAnomalyDetector(self.config.behavior_window)
        self.sequence_model = APISequenceModel(window=self.config.sequence_window)
        self.timing = TimingProfiler(self.config.timing_sigma_threshold)
        self.privileges = PrivilegeMonitor(self.config.privilege_drift_threshold)
        self.pivots = PivotTracker(self.config.pivot_depth_threshold)
        self.graph = GraphModel()
        self.fingerprinter = IdentityFingerprinter(self.config.multi_actor_window)
        self.attack_predictor = AttackSequencePredictor(
            contamination=self.config.attack_prediction_contamination,
            score_multiplier=self.config.attack_prediction_score_multiplier,
        )
        self.recent_sequences: Dict[str, Deque[ActivityEvent]] = defaultdict(deque)

    def bootstrap_model(self, baseline_sequences: List[List[ActivityEvent]]) -> None:
        if baseline_sequences:
            self.attack_predictor.fit(baseline_sequences)

    def _get_account(self, user_id: str) -> AccountState:
        return self.accounts.setdefault(user_id, AccountState(user_id=user_id))

    def assess_event(
        self,
        identity: IdentityContext,
        event: ActivityEvent,
        privilege_change: PrivilegeChange | None = None,
    ) -> RiskAssessment:
        account = self._get_account(identity.user_id)
        account.update_session(
            SessionState(
                session_id=identity.session_id or f"session-{identity.user_id}",
                device_id=identity.device_id,
                created_at=identity.timestamp,
                last_seen=identity.timestamp,
                ip=identity.ip,
            )
        )

        signals: List[RiskSignal] = []

        fingerprint_signal = self.fingerprinter.detect_multi_actor(identity)
        if fingerprint_signal:
            signals.append(fingerprint_signal)

        behavior_signal = self.behavior.assess(identity.user_id, event)
        if behavior_signal:
            signals.append(behavior_signal)

        sequence_signal = self.sequence_model.score(identity.user_id, event)
        if sequence_signal:
            signals.append(sequence_signal)

        timing_signal = self.timing.assess(event)
        if timing_signal:
            signals.append(timing_signal)

        privilege_signals = self.privileges.assess(account, privilege_change)
        signals.extend(privilege_signals)

        pivot_signal = self.pivots.assess(event)
        if pivot_signal:
            signals.append(pivot_signal)

        graph_signal = self.graph.assess(identity.user_id, identity.ip, identity.device_id)
        if graph_signal:
            signals.append(graph_signal)

        sequence = self._update_sequence(identity.user_id, event)
        ml_signal = self.attack_predictor.score(sequence)
        if ml_signal:
            signals.append(ml_signal)

        total_score = sum(signal.score for signal in signals)
        action = self.config.evaluate_action(total_score)
        assessment = RiskAssessment(
            total_score=total_score,
            signals=signals,
            action=action,
            account_frozen=False,
            session_invalidated=False,
        )

        if action == "freeze_account":
            assessment.account_frozen = True
            account.frozen = True
        if action == "force_logout":
            account.expire_session(identity.session_id or "")
            assessment.session_invalidated = True

        return assessment

    def _update_sequence(self, user_id: str, event: ActivityEvent) -> Deque[ActivityEvent]:
        queue = self.recent_sequences[user_id]
        queue.append(event)
        if len(queue) > self.config.sequence_window:
            queue.popleft()
        if not self.attack_predictor.is_trained and len(queue) >= max(3, self.config.sequence_window // 2):
            self.attack_predictor.update_baseline(queue)
        return queue

    def freeze_account(self, user_id: str) -> None:
        account = self._get_account(user_id)
        account.frozen = True

    def reset_sessions(self, user_id: str) -> None:
        account = self._get_account(user_id)
        account.sessions.clear()

    def account_state(self, user_id: str) -> AccountState:
        return self._get_account(user_id)

    def summary(self, user_id: str) -> Dict[str, object]:
        account = self._get_account(user_id)
        return {
            "frozen": account.frozen,
            "active_sessions": list(account.sessions.keys()),
            "behavior": self.behavior.volume_summary(user_id),
            "recent_sequence": self.sequence_model.recent_sequence(user_id),
        }
