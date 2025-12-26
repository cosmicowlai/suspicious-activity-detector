from __future__ import annotations

import logging
import os
from typing import Any, Mapping, MutableMapping, Optional

import httpx
from fastapi.encoders import jsonable_encoder


logger = logging.getLogger(__name__)


def resolve_webhook_url(default: Optional[str] = None) -> Optional[str]:
    """Return the assessment webhook URL from environment or provided default."""
    return os.getenv("ASSESSMENT_WEBHOOK_URL", default)


def build_assessment_payload(
    *,
    assessment: Mapping[str, Any],
    identity: Mapping[str, Any],
    event: Mapping[str, Any],
    privilege_change: Optional[Mapping[str, Any]] = None,
    task_id: Optional[str] = None,
    source: str = "sync",
) -> MutableMapping[str, Any]:
    """Create a JSON-serializable payload describing an assessment result."""
    payload: MutableMapping[str, Any] = {
        "task_id": task_id,
        "source": source,
        "identity": identity,
        "event": event,
        "privilege_change": privilege_change,
        "assessment": assessment,
    }
    return jsonable_encoder(payload)  # normalizes datetimes, sets, and other non-JSON types


def deliver_webhook(webhook_url: Optional[str], payload: Mapping[str, Any]) -> None:
    """Send the payload to the configured webhook endpoint if present."""
    if not webhook_url:
        return

    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.post(str(webhook_url), json=payload)
            response.raise_for_status()
    except Exception as exc:  # pragma: no cover - we log failures without failing the assessment
        logger.warning("Failed to deliver assessment webhook to %s: %s", webhook_url, exc)
