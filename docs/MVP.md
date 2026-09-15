# Phase 1 MVP

## Objective

Deliver a safe single-machine foundation that proves PrivaShield can ingest security telemetry, normalize and persist it, stream it to a local UI, enrich selected events with a local model, manage observe-only policy, and maintain a verifiable audit trail.

Phase 1 intentionally avoids autonomous blocking. The purpose is to establish contracts and observability before granting the system authority over network or endpoint state.

## MVP components

1. **API/control plane** . FastAPI, Pydantic, SQLAlchemy
2. **Database** . PostgreSQL with Alembic migrations
3. **Event transport** . Redis Streams
4. **Worker** . asynchronous event processor and AI enrichment worker
5. **Model provider** . Ollama-compatible local adapter with timeout/circuit-breaker behavior
6. **Sensor** . simulated event source plus one local telemetry adapter
7. **Audit chain** . append-only canonical audit records with SHA-256 chain linkage
8. **Dashboard** . local React/Next.js shell with live activity, alerts, AI analysis, policy/configuration, and health
9. **Packaging** . Docker Compose, environment template, initialization script, and documented uninstall/data cleanup

## MVP user flows

### Flow A. Event ingestion
Sensor -> ingestion API/adapter -> validate -> normalize -> Redis Stream -> worker -> PostgreSQL -> dashboard feed.

### Flow B. AI summary
Analyst selects an event/alert -> API creates analysis request -> worker loads bounded evidence -> local model -> schema validation -> persisted analysis -> dashboard update.

### Flow C. Classification
Content/evidence reference -> deterministic recognizers + optional local model -> classification findings -> policy evaluation -> alert only in Phase 1.

### Flow D. Policy change
Authenticated operator changes observe-only threshold/configuration -> validation -> versioned policy persisted -> audit record -> workers receive updated policy revision.

### Flow E. Audit verification
Operator requests verification -> service recomputes canonical hashes and chain links -> reports valid, invalid, or incomplete state without rewriting history.

## Phase 1 API surface

At minimum:

- `/api/v1/health`
- `/api/v1/system/status`
- `/api/v1/events`
- `/api/v1/events/{id}`
- `/api/v1/events/stream`
- `/api/v1/alerts`
- `/api/v1/alerts/{id}`
- `/api/v1/classifications`
- `/api/v1/analysis`
- `/api/v1/analysis/{id}`
- `/api/v1/policies`
- `/api/v1/policies/{id}`
- `/api/v1/sources`
- `/api/v1/configuration`
- `/api/v1/models`
- `/api/v1/audit`
- `/api/v1/audit/verify`

## Repository layout target

```text
privashield/
  apps/
    api/
    dashboard/
    worker/
  packages/
    domain/
    policy/
    ai/
    audit/
    telemetry/
  sensors/
    simulator/
    network/
    filesystem/
  enforcement/
    interface/
  migrations/
  tests/
    unit/
    integration/
    e2e/
    security/
  docs/
  scripts/
  deploy/
    compose/
```

The exact tree may evolve through ADRs, but domain contracts should remain independent from framework adapters.

## Implementation sequence

1. Establish domain models and IDs.
2. Create FastAPI skeleton and health/status endpoints.
3. Add PostgreSQL schema and migrations.
4. Add Redis Streams transport abstraction.
5. Implement canonical event ingest and query APIs.
6. Add simulator and live event streaming to the UI.
7. Implement alert and classification persistence.
8. Implement local model provider abstraction and one Ollama-compatible adapter.
9. Add asynchronous threat-summary/classification jobs.
10. Add versioned observe-only policy model.
11. Add hash-chained audit records and verifier.
12. Add the first real local sensor adapter.
13. Complete integration/e2e/security tests.
14. Package with Docker Compose and documented bootstrap.

## Acceptance tests

The MVP must prove:

- malformed events are rejected with structured errors
- duplicate event handling is deterministic
- AI can be unavailable without stopping ingestion
- the dashboard receives new events without polling the full dataset
- sensitive source evidence is not written to application logs
- policy changes produce immutable audit entries
- audit-chain tampering is detected
- the system starts from a clean machine using the documented deployment process
- containers restart without corrupting persistent state
- backup/restore can recover PostgreSQL state
- Phase 1 has no code path that silently enables destructive enforcement

## Exit criteria

Phase 1 exits only when its acceptance criteria are automated where practical, architecture/API/data documentation matches the implementation, and open high-severity defects affecting data integrity, authorization, or auditability are resolved.
