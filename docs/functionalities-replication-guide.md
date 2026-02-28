# Suspicious Activity Detector – Functionalities Replication Guide

This document explains every major functionality in this app and includes a copy/paste prompt you can give to Codex to rebuild the same capabilities in another project.

## 1) What this app does

The application is a risk engine that evaluates identity context + activity events and outputs:
- a numeric risk score,
- a list of risk signals explaining why,
- a recommended action (`monitor`, `force_logout`, `freeze_account`).

It combines deterministic rules and lightweight statistical anomaly detection.

## 2) Core domain model to replicate

Implement these core entities:
- `IdentityContext`: user/device/session/network identity and current privileges.
- `ActivityEvent`: API event telemetry (endpoint, latency, payload sizes, service, trace id, metadata).
- `PrivilegeChange`: before/after roles and privileges.
- `RiskSignal`: named signal with score + human-readable detail.
- `RiskAssessment`: total score, action, signals, and action side effects.
- `AccountState`: per-user sessions, frozen state, privilege history.
- `SessionState`: active session snapshot.
- `TimingStats`: rolling mean/variance helper for latency anomalies.

## 3) Risk scoring pipeline (engine behavior)

For each incoming event, run these checks in sequence and aggregate scores:

1. **Session/account state update**
   - Ensure account exists.
   - Upsert current session state.

2. **Identity fingerprint + multi-actor detection**
   - Build fingerprint hash from device + ip + geo + user-agent + user.
   - If fingerprint changes within a short time window, add `multi_actor_detection` signal.

3. **Behavior anomaly detector**
   - Keep rolling per-user event window.
   - Detect request-rate surge (`behavior_rate_anomaly`).
   - Detect sudden endpoint dominance (`behavior_endpoint_anomaly`).

4. **API sequence anomaly detector**
   - Track Markov-like endpoint transitions.
   - Flag highly improbable transition from previous endpoint (`api_sequence_anomaly`).

5. **Timing profiler**
   - Track per-endpoint latency stats.
   - Flag outliers using sigma threshold (`timing_anomaly`) after minimum warmup samples.

6. **Privilege monitor**
   - Detect immediate new privilege additions (`privilege_escalation`).
   - Detect multi-step upward drift over recent change history (`privilege_drift`).

7. **Microservice pivot tracker**
   - Track services visited in a trace.
   - Flag deep cross-service pivots (`microservice_pivot`).

8. **Graph model checks**
   - Track relationships across user ↔ ip ↔ device.
   - Flag shared risky IPs across many accounts (`shared_ip_risk`).
   - Flag excessive device sprawl per user (`device_sprawl`).

9. **ML/statistical attack sequence predictor**
   - Featurize recent sequence (length, admin hits, errors, service diversity, latency, burst bytes out).
   - Maintain baseline stats.
   - Score via z-score budget and emit `ml_attack_prediction` when anomalous.

10. **Action mapping and side effects**
   - Sum all signal scores.
   - Threshold to action:
     - high: `freeze_account`
     - medium: `force_logout`
     - else: `monitor`
   - Apply side effects:
     - freeze toggles account frozen state,
     - force logout invalidates current session.

## 4) Configuration knobs to expose

Expose configuration values equivalent to:
- high/medium risk thresholds,
- sequence window length,
- behavior time window,
- timing sigma threshold,
- privilege drift threshold,
- multi-actor detection window,
- pivot depth threshold,
- attack prediction contamination + score multiplier.

## 5) API surface to replicate

Provide a service interface with these endpoints:
- `GET /health` → readiness.
- `POST /assess` → synchronous risk assessment.
- `POST /assess/async` → queue async assessment task and return task id.
- `GET /tasks/{task_id}` → poll async result (`pending`/`completed`).
- `GET /accounts/{user_id}/summary` → current account + behavior summary.
- `POST /accounts/{user_id}/freeze` → freeze account.
- `POST /accounts/{user_id}/reset-sessions` → clear sessions.

## 6) Async + persistence + webhook behavior

To match this app behavior:
- Use Celery for async assessment jobs.
- Use Redis as broker/result backend.
- Persist assessments in MongoDB with unique `task_id` index.
- Send webhook callbacks (sync and async flows) to `ASSESSMENT_WEBHOOK_URL`.
- Webhook payload should include: task_id, source (`sync`/`async`), identity, event, optional privilege_change, and final assessment.

## 7) Operational flow you should preserve

1. Client sends identity + event (+ optional privilege change).
2. Engine produces signals and action.
3. API returns structured assessment.
4. Optional side effects mutate account/session state.
5. Optional webhook posts normalized JSON payload to backend.
6. Async path stores result and supports later polling.

## 8) Copy/paste prompt for Codex

Use the prompt below in your target repository:

```text
Build a production-ready suspicious activity detection module and API with feature parity to the following specification.

Architecture requirements:
- Language: Python.
- API framework: FastAPI.
- Async worker: Celery.
- Broker/backend: Redis.
- Persistence: MongoDB.
- HTTP client for callbacks: httpx.
- Include tests with pytest.

Core models:
- IdentityContext(user_id, device_id, ip, geo, user_agent, session_id, roles, privileges, timestamp)
- ActivityEvent(timestamp, endpoint, method, status_code, latency_ms, bytes_in, bytes_out, service, trace_id, metadata)
- PrivilegeChange(previous_roles, new_roles, previous_privileges, new_privileges, timestamp)
- RiskSignal(name, score, detail)
- RiskAssessment(total_score, signals, action, account_frozen, session_invalidated)
- SessionState(session_id, device_id, created_at, last_seen, ip)
- AccountState(user_id, sessions, frozen, privilege_history, last_fingerprint)
- TimingStats(count, mean, m2 with variance/stddev properties)

Engine behavior:
- Create a RiskEngine with per-user account state and sub-detectors.
- Assessment pipeline must include:
  1) multi-actor identity fingerprint detection,
  2) behavior anomaly (request-rate surge and endpoint-dominance spike),
  3) API sequence anomaly via transition probabilities,
  4) timing anomaly via sigma outlier detection,
  5) privilege escalation + privilege drift detection,
  6) microservice pivot detection by trace depth,
  7) graph-based shared-IP and device-sprawl detection,
  8) lightweight statistical attack-sequence predictor using engineered features and z-score budget.
- Aggregate all signal scores into total risk score.
- Action policy:
  - score >= high threshold => freeze_account
  - score >= medium threshold => force_logout
  - else => monitor
- Apply side effects to account/session state.

Config:
- Expose configurable thresholds and windows for all detector components and action policy.

API endpoints:
- GET /health
- POST /assess (sync assessment)
- POST /assess/async (enqueue assessment, return task_id)
- GET /tasks/{task_id} (pending/completed + assessment)
- GET /accounts/{user_id}/summary
- POST /accounts/{user_id}/freeze
- POST /accounts/{user_id}/reset-sessions

Async/persistence behavior:
- Celery task processes queued assessments and stores results in MongoDB by task_id.
- MongoDB repository should support save and fetch by task_id.

Webhook behavior:
- Read callback URL from ASSESSMENT_WEBHOOK_URL.
- For both sync and async completion, POST a JSON payload containing:
  task_id, source, identity, event, privilege_change, assessment.
- Webhook failures should be logged but not break assessment flow.

Deliverables:
- Clean module structure separating models, engine, monitors, API, async tasks, persistence, webhook utils.
- Type hints throughout.
- Unit tests for engine scoring behavior and API endpoints.
- README with local run instructions for API, worker, Redis, and MongoDB.
```

## 9) Replication checklist

Use this checklist when reviewing generated code:
- [ ] All 8 detector families implemented.
- [ ] Risk signals are explainable (`name`, `score`, `detail`).
- [ ] Threshold-based action mapping works.
- [ ] Freeze/logout side effects applied in engine state.
- [ ] Sync API + async queue + task polling all functional.
- [ ] Mongo persistence of async results.
- [ ] Optional webhook dispatch in both sync and async paths.
- [ ] Basic tests cover engine and API behavior.

