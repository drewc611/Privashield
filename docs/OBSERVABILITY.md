# Observability

## Goals

Operators must be able to answer: Is PrivaShield healthy? Is telemetry arriving? Are detections delayed? Is AI degraded? What policy is active? Has enforcement changed? Is the audit chain intact?

## Logs

Use structured logs with timestamp, level, service, event name, request/correlation ID, and bounded context. Logs must not contain passwords, tokens, private keys, full authorization headers, arbitrary packet payloads, or full sensitive model prompts by default.

## Metrics

Core metrics should include:

- events ingested/accepted/rejected by source and type
- processing latency and queue lag
- detector findings/alerts by severity
- model jobs queued/running/succeeded/failed and latency
- policy evaluation counts/outcomes
- API latency/error rate
- database connection/transaction health
- Redis stream depth/consumer lag
- sensor last-event age
- dropped or sampled telemetry counts
- audit verification result/last verified sequence
- future enforcement actions, failures, rollbacks, and reconciliation drift

Avoid high-cardinality labels containing user IDs, IP addresses, request payloads, or other sensitive values unless the deployment explicitly accepts that cost/privacy tradeoff.

## Traces

OpenTelemetry-compatible tracing is recommended across API, event publication, worker processing, AI calls, and policy evaluation. Sensitive payloads must not be attached to spans by default.

## Health endpoints

- liveness: process is running
- readiness: service can perform its required role
- dependency status: database, event bus, model runtime, sensors, audit state

AI-provider failure should show a degraded component rather than necessarily making the core API unready.

## Alert conditions

Examples:

- no events from an enabled source beyond expected interval
- sustained queue lag
- repeated ingestion rejection spike
- database unavailable
- audit verification failure
- model failure rate above threshold
- disk pressure
- configuration/policy reconciliation failure
- later: enforcement adapter drift or repeated rollback

## Dashboard

The dashboard presents summarized health but is not the source of truth. Backend health/status APIs remain independently queryable.
