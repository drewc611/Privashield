# Test Strategy

## Objectives

Testing must demonstrate correctness, security, resilience, performance, and safe failure behavior. Because PrivaShield can eventually alter network and endpoint state, passing happy-path tests is not sufficient.

## Test layers

### Unit tests
Cover domain models, validation, policy evaluation, canonicalization, hashing, parsers, adapters, utility functions, and deterministic decision logic.

### Contract tests
Verify API schemas, event envelopes, model-provider interfaces, sensor interfaces, and enforcement interfaces remain compatible.

### Integration tests
Run against real PostgreSQL and Redis containers and local service boundaries. Validate transaction behavior, event delivery, retries, migrations, and worker processing.

### End-to-end tests
Exercise representative flows from sensor/simulator through ingestion, persistence, processing, API, and dashboard state.

### Security tests
Include:

- authentication/authorization tests when implemented
- injection and malformed input
- path traversal and unsafe file references
- XSS payloads in telemetry/model output
- secret redaction
- oversized requests
- rate/resource abuse
- policy privilege checks
- audit tampering

### Fuzz/property tests
Use fuzzing or property-based tests for packet/log/file parsers, canonicalization, policy parsers, CIDR/IP processing, and other hostile-input boundaries.

### Performance tests
Measure ingestion throughput, event-stream latency, database query behavior, queue lag, AI job latency, dashboard stream behavior, and later enforcement latency.

### Failure-injection tests
Simulate:

- PostgreSQL unavailable
- Redis unavailable
- model runtime unavailable or slow
- worker crash/restart
- malformed model output
- disk pressure where practical
- sensor restart
- later enforcement adapter timeout or partial failure

### AI evaluation
Use a versioned evaluation corpus for classification, summaries, prompt-injection resistance, schema compliance, and hallucinated remediation. Model/profile changes must be compared against the baseline.

## Phase 1 critical tests

- event validation and normalization
- event deduplication/idempotency
- persistence and query
- stream reconnect behavior
- AI outage does not stop ingestion
- malformed model output rejected
- sensitive fields excluded from logs
- audit hash chain creation/verification
- tampered audit row detected
- policy activation restricted to observe/alert
- migrations on clean and existing databases
- Compose cold-start smoke test

## Coverage

Coverage percentage is a signal, not the objective. Critical security decision code, audit logic, parsers, policy, and authorization require meaningful branch/negative tests even when aggregate coverage appears high.

## Test data

Use synthetic or sanitized fixtures only. Include adversarial fixtures specifically designed to exercise parser limits, prompt injection, malformed protocol fields, encodings, and UI rendering.

## CI gates

Before merge, the project should eventually require:

- format/lint
- static type checks
- unit/contract tests
- integration tests
- secret scan
- dependency/SCA scan
- SAST
- container scan when images exist
- documentation/link checks

Release gates add e2e, performance/security qualification, SBOM/artifact verification, and migration/rollback tests.
