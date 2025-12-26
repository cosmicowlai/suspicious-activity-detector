from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Mapping, MutableMapping, Optional

from pymongo import MongoClient

from .models import RiskAssessment, RiskSignal


class AssessmentRepository:
    """MongoDB-backed repository for assessment results and inputs."""

    def __init__(self, uri: str, database: str = "suspicious_activity") -> None:
        self.client = MongoClient(uri)
        self.db = self.client[database]
        self.assessments = self.db["assessments"]
        self.assessments.create_index("task_id", unique=True)

    def save_assessment(
        self,
        task_id: str,
        identity: Mapping[str, Any],
        event: Mapping[str, Any],
        assessment: RiskAssessment,
        privilege_change: Optional[Mapping[str, Any]] = None,
    ) -> None:
        document: MutableMapping[str, Any] = {
            "task_id": task_id,
            "identity": identity,
            "event": event,
            "privilege_change": privilege_change,
            "assessment": self.serialize_assessment(assessment),
            "created_at": datetime.utcnow(),
        }

        self.assessments.replace_one({"task_id": task_id}, document, upsert=True)

    def get_assessment(self, task_id: str) -> Optional[Dict[str, Any]]:
        document = self.assessments.find_one({"task_id": task_id})
        if document is None:
            return None

        document.pop("_id", None)
        return document

    def serialize_assessment(self, assessment: RiskAssessment) -> Dict[str, Any]:
        return {
            "total_score": assessment.total_score,
            "action": assessment.action,
            "account_frozen": assessment.account_frozen,
            "session_invalidated": assessment.session_invalidated,
            "signals": [self._serialize_signal(signal) for signal in assessment.signals],
        }

    def _serialize_signal(self, signal: RiskSignal) -> Dict[str, Any]:
        return {"name": signal.name, "score": signal.score, "detail": signal.detail}
