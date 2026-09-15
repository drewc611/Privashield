# Development Guide

## Prerequisites

Phase 1 development targets:

- Git
- Docker Engine / Docker Desktop with Compose v2
- Python 3.12+
- Node.js LTS
- a local Ollama-compatible runtime for AI-enabled development, optional for core ingestion tests

Linux is the reference platform for network sensors and future enforcement. Backend/UI development should remain possible on macOS and Windows where privileged networking is not required.

## Target repository layout

```text
apps/
  api/          FastAPI control plane
  worker/       asynchronous processing and AI enrichment
  dashboard/    Next.js/TypeScript UI
packages/
  domain/       framework-independent models/contracts
  telemetry/    normalized ingestion/event interfaces
  ai/           model-provider interfaces
  policy/       policy evaluation contracts
  audit/        canonicalization/hash-chain logic
sensors/
  simulator/
  network/
  filesystem/
enforcement/
  interface/    enforcement contract and safe mock
migrations/
tests/
scripts/
deploy/compose/
docs/
```

## Local workflow

1. Clone the repository.
2. Copy the documented environment template once it exists.
3. Start PostgreSQL and Redis through Compose.
4. Run migrations.
5. Start the API and worker.
6. Start the dashboard.
7. Start the simulator or approved local sensor.
8. Run the smoke test and verify the event appears in the dashboard.

The final commands will be added with the Phase 1 scaffold rather than invented in documentation before scripts exist.

## Python standards

- type annotations for public/service-layer interfaces
- Pydantic for external contracts
- SQLAlchemy for persistence
- Alembic for migrations
- formatting/linting enforced in CI
- no arbitrary shell execution from request/model data
- dependency injection around transports, storage, clocks, model providers, and enforcement backends to support testing

## TypeScript/UI standards

- strict TypeScript
- generated or shared API types where practical
- no rendering of untrusted telemetry/model output as raw HTML
- accessible keyboard/navigation behavior for operator controls
- high-impact actions require clear state and confirmation

## Configuration

Configuration is layered:

1. safe code defaults
2. configuration file/environment overrides
3. persisted operator configuration for approved runtime settings
4. secret references kept outside ordinary configuration responses

Do not introduce undocumented environment variables.

## Database migrations

Every schema change uses Alembic. Migrations must be reviewed with rollback/restore implications. Destructive migrations require backup/restore validation.

## Feature flags and modes

Risky features use explicit capability flags or operating modes. `observe` is the default for new detection/enforcement integrations until acceptance tests justify stronger behavior.

## Test before commit

At minimum, run the formatter, linter, type checks, affected unit tests, and relevant integration tests. Security-sensitive parsers or enforcement changes require the tests defined in `TESTING.md`.

## Test data

Use synthetic or sanitized fixtures. Do not commit real credentials, customer logs, PHI, private packet captures, or other sensitive data.

## Documentation

Update docs in the same PR when behavior, API, schema, deployment, security assumptions, or failure modes change.
