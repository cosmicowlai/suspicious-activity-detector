# suspicious-activity-detector

A production-ready suspicious activity detection engine in Python that blends deterministic security rules with lightweight AI-based anomaly detection. The engine ingests identity and activity events, calculates rich risk signals, and recommends actions such as forced logout or account freeze.

## Features
- **Identity fingerprinting:** Device/IP/UA-based fingerprints with rapid multi-actor detection.
- **Behavior-based anomaly detection:** Per-account traffic baselines, burst and endpoint-skew detection.
- **API sequence modeling:** Markov-chain transition monitoring to flag unusual flows.
- **Timing fingerprinting:** Rolling latency profiling to highlight outlier responses.
- **Privilege escalation & drift:** Detect sudden role/privilege changes and slow privilege creep.
- **Session reset & forced logout:** Session invalidation tied to risk actions.
- **Account freeze / Shield Mode:** Freeze risky accounts until reviewed.
- **Predictive risk scoring:** Combined weighted signals with configurable thresholds.
- **Multi-actor detection:** Rapid identification of diverging fingerprints per account.
- **Behavior graph modeling:** Relationship tracking between users, IPs, and devices for shared-signal risk.
- **Microservice pivot tracking:** Detect suspicious cross-service pivots inside traces.
- **ML-based attack-sequence prediction:** Lightweight statistical model over engineered features for attack-like sequences.
- **Identity/behavior verification:** Continuous consistency checks and state summaries.

## Getting started

### Install dependencies
```
pip install -r requirements.txt
```

### Run the demo
```
python examples/demo.py
```
The demo bootstraps a benign baseline, applies a privilege escalation, and evaluates a high-risk export action. It prints the combined risk signals and the recommended action.

## REST API service

Expose the detector as a FastAPI service:

```
uvicorn suspicious_activity_detector.api:app --host 0.0.0.0 --port 8000 --reload
```

Key endpoints:
- `GET /health` - basic readiness check.
- `POST /assess` - submit an identity, activity event, and optional privilege change for immediate scoring.
- `POST /assess/async` - enqueue an assessment to be processed by a Celery worker.
- `GET /tasks/{task_id}` - fetch an asynchronous assessment result (returns `pending` until completed).
- `GET /accounts/{user_id}/summary` - retrieve the current account state and behavioral summary.
- `POST /accounts/{user_id}/freeze` - mark an account as frozen.
- `POST /accounts/{user_id}/reset-sessions` - clear active sessions.

Example assessment request:

```bash
curl -X POST http://localhost:8000/assess \
  -H "Content-Type: application/json" \
  -d '{
    "identity": {
      "user_id": "alice",
      "device_id": "device-1",
      "ip": "203.0.113.10",
      "geo": "US",
      "user_agent": "Mozilla/5.0",
      "session_id": "sess-1",
      "roles": ["user"],
      "privileges": ["read"],
      "timestamp": "2024-01-01T00:00:00Z"
    },
    "event": {
      "timestamp": "2024-01-01T00:00:00Z",
      "endpoint": "/admin/export",
      "method": "POST",
      "status_code": 200,
      "latency_ms": 120,
      "bytes_in": 256,
      "bytes_out": 4096,
      "service": "admin",
      "trace_id": "trace-1",
      "metadata": {"source": "api-doc"}
    },
    "privilege_change": {
      "previous_roles": ["user"],
      "new_roles": ["user", "admin"],
      "previous_privileges": ["read"],
      "new_privileges": ["read", "write"],
      "timestamp": "2024-01-01T00:00:00Z"
    }
  }'
```

## Library usage
```python
from datetime import datetime
from suspicious_activity_detector import ActivityEvent, EngineConfig, IdentityContext, RiskEngine

config = EngineConfig()
engine = RiskEngine(config)
now = datetime.utcnow()

identity = IdentityContext(
    user_id="alice",
    device_id="device-123",
    ip="198.51.100.10",
    geo="US",
    user_agent="Mozilla/5.0",
    session_id="sess-1",
    roles={"user"},
    privileges={"read"},
    timestamp=now,
)

event = ActivityEvent(
    timestamp=now,
    endpoint="/payments/transfer",
    method="POST",
    status_code=200,
    latency_ms=240,
    bytes_in=800,
    bytes_out=2048,
    service="payments",
    trace_id="trace-abc",
)

assessment = engine.assess_event(identity, event)
print(assessment.total_score, assessment.action)
print(engine.summary(identity.user_id))
```

## Containerization

Build and run the API as a container:

```
docker build -t suspicious-activity-detector .
docker run -p 8000:8000 suspicious-activity-detector
```

Or start it with Docker Compose:

```
docker-compose up --build
```

The Compose stack now includes Redis (for Celery) and MongoDB (for persistence). To run the asynchronous flow locally:

```
docker-compose up --build
```

Then enqueue and poll a task:

```bash
curl -X POST http://localhost:8000/assess/async \
  -H "Content-Type: application/json" \
  -d '{...}'

curl http://localhost:8000/tasks/<task_id>
```

## Tests
```
pytest
```
