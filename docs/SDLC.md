# Software Development Lifecycle

PrivaShield follows an iterative SDLC with additional gates for security-sensitive functionality.

## Stage 1. Define

Required outputs:

- problem statement and user outcome
- functional/non-functional requirements
- security/privacy impact
- acceptance criteria
- dependencies and assumptions

Features that change a trust boundary or privileged capability should identify whether an ADR is required.

## Stage 2. Design

Required as applicable:

- architecture/data-flow update
- API/schema changes
- threat-model update
- authorization model
- failure behavior
- rollback design
- observability requirements
- migration/compatibility approach

## Stage 3. Implement

Implementation expectations:

- least privilege
- typed/validated interfaces
- bounded inputs/resources
- no hard-coded secrets
- deterministic handling of failures
- tests written with the behavior
- docs updated with the implementation

## Stage 4. Verify

Verification includes the applicable combination of:

- unit tests
- contract tests
- integration tests
- end-to-end tests
- security tests
- parser fuzzing
- performance/load tests
- failure-injection tests
- upgrade/rollback tests
- AI evaluation/regression tests

## Stage 5. Review

Pull requests require code review. Security-sensitive changes receive additional scrutiny for threat model, permissions, data handling, and rollback.

## Stage 6. Release

A release candidate must satisfy `RELEASE.md`, including scans, test gates, changelog/release notes, migration review, artifact/SBOM requirements, and rollback preparation.

## Stage 7. Operate

Operations include:

- health and alert monitoring
- incident response
- backup/restore
- vulnerability response
- dependency/model updates
- audit verification
- configuration drift review

## Stage 8. Learn

Post-incident findings, false-positive/false-negative observations, performance data, and user feedback feed back into requirements and tests.

## Security gate classes

### Standard
UI/documentation/non-privileged changes with no material trust-boundary change.

### Security-sensitive
Parsers, authentication, authorization, crypto, model handling, policy, sensitive-data storage, external integrations.

### Privileged/enforcement
Kernel/network changes, isolation, credential revocation, session termination, file blocking/deletion, or any action that can cause availability impact.

Privileged/enforcement changes require explicit failure-mode and rollback tests before release.

## Definition of ready

A work item is ready for implementation when its objective, acceptance criteria, security/privacy impact, and major interfaces are understood well enough to test.

## Definition of done

A work item is done only when implementation, tests, docs, observability, migration considerations, security review requirements, and acceptance criteria are complete.
