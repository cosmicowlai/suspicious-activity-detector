from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Dict, Tuple

from .models import IdentityContext, RiskSignal


class IdentityFingerprinter:
    def __init__(self, multi_actor_window: timedelta):
        self.multi_actor_window = multi_actor_window
        self.recent_fingerprints: Dict[str, Tuple[str, datetime]] = {}

    def fingerprint(self, identity: IdentityContext) -> str:
        payload = "|".join(
            [
                identity.device_id,
                identity.ip,
                identity.geo,
                identity.user_agent,
                identity.user_id,
            ]
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def detect_multi_actor(self, identity: IdentityContext) -> RiskSignal | None:
        fingerprint = self.fingerprint(identity)
        previous = self.recent_fingerprints.get(identity.user_id)
        self.recent_fingerprints[identity.user_id] = (fingerprint, identity.timestamp)
        if previous is None:
            return None
        previous_fp, previous_ts = previous
        if previous_fp != fingerprint and identity.timestamp - previous_ts <= self.multi_actor_window:
            return RiskSignal(
                name="multi_actor_detection",
                score=25.0,
                detail="Account used from multiple distinct fingerprints within a short window",
            )
        return None
