# PrivaShield Documentation

This directory is the engineering source of truth for the project.

## Product and requirements

- `PROJECT_CHARTER.md` . mission, scope, principles, stakeholders, and success criteria
- `REQUIREMENTS.md` . functional and non-functional requirements
- `MVP.md` . Phase 1 scope, exclusions, acceptance criteria, and implementation sequence
- `ROADMAP.md` is maintained at the repository root

## Architecture and contracts

- `ARCHITECTURE.md` . system context, components, trust boundaries, data flows, and technology choices
- `API.md` . control-plane API contract
- `DATA_MODEL.md` . canonical domain models and relationships
- `THREAT_MODEL.md` . assets, actors, attack surfaces, abuse cases, and mitigations
- `SECURITY_ARCHITECTURE.md` . privileged boundaries, enforcement design, secrets, cryptography, and authorization
- `PRIVACY.md` . data minimization, retention, local processing, and sensitive-data handling
- `AI_MODEL_GOVERNANCE.md` . model authority, evaluation, prompt-injection defenses, and model lifecycle
- `NETWORK_ENFORCEMENT.md` . sensor and enforcement modes, fast-path constraints, fail behavior, and rollback
- `AUDIT_LOGGING.md` . tamper-evident audit chain and verification rules

## Engineering and delivery

- `DEVELOPMENT.md` . local engineering workflow and repository layout
- `SDLC.md` . lifecycle stages and required artifacts
- `TESTING.md` . test strategy and quality gates
- `DEPLOYMENT.md` . local and future deployment models
- `OPERATIONS.md` . backup, restore, incident, upgrade, and recovery expectations
- `OBSERVABILITY.md` . logs, metrics, traces, health, and alerting
- `RELEASE.md` . release qualification, versioning, signing, and rollback
- `SUPPLY_CHAIN.md` . dependency, SBOM, artifact integrity, and provenance policy
- `COMPLIANCE.md` . control mapping approach without claiming certification

## Decisions

Architecture Decision Records live under `adr/`. ADRs record consequential decisions and why alternatives were rejected.

## Documentation rule

A change that modifies external behavior, an API, a schema, a trust boundary, a privileged action, storage/retention, deployment requirements, or failure behavior is incomplete until its documentation is updated.
