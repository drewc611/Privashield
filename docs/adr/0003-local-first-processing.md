# ADR-0003: Local-first processing and inference

- Status: Accepted
- Date: 2026-09-15

## Context

PrivaShield processes security telemetry that can contain credentials, personal data, internal network information, proprietary content, and incident evidence. Mandatory external telemetry or hosted AI would expand the privacy and trust boundary significantly.

## Decision

Core processing, storage, and AI inference are local by default. The MVP has no required cloud service and sends no usage analytics to the project maintainers.

Future external integrations are opt-in, explicitly configured, and must document what data leaves the host.

## Consequences

Benefits:

- reduced default data exposure
- supports disconnected and sensitive environments
- predictable privacy boundary
- users retain control of security telemetry

Costs:

- local compute/storage requirements
- model performance depends on available hardware
- maintainers receive less automatic diagnostic information

## Alternatives considered

### Mandatory hosted AI/API
Rejected because it conflicts with the privacy goals and restricts offline/sensitive deployments.

### Anonymous telemetry enabled by default
Rejected because security metadata can be sensitive and "anonymous" telemetry can still create unexpected data flows. Any future diagnostic telemetry must be opt-in.
