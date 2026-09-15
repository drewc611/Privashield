# Deployment

## Phase 1 reference deployment

The supported MVP topology is one Linux host using Docker Compose.

Planned services:

- `api` . FastAPI control plane
- `worker` . asynchronous event/AI processing
- `dashboard` . local Next.js UI
- `postgres` . durable state
- `redis` . event transport
- `ollama` or compatible local model runtime . optional for core operation, required for AI features
- `sensor-*` . optional local sensors with narrowly scoped privileges

## Network exposure

Default bindings should be localhost-only. PostgreSQL, Redis, model runtime, and privileged adapters should not be published to untrusted interfaces.

Remote access is unsupported until authentication, TLS, and documented hardening are present.

## Persistent data

Persist at least:

- PostgreSQL data
- approved model files/cache as needed
- configuration/secret mounts
- optional evidence storage

Redis should not be treated as the source of truth for durable security history.

## Environment configuration

A future `.env.example` may document non-secret settings. Production secrets must use mounted secret files, an OS secret store, or a secret manager rather than being committed to source.

## Startup order

1. PostgreSQL and Redis become healthy.
2. Database migrations run.
3. API starts and reports readiness.
4. Workers connect.
5. Dashboard starts.
6. Sensors start after the ingestion path is ready.
7. AI provider health is reported independently and does not block core readiness unless explicitly required.

## Upgrades

Before upgrade:

- read release notes
- back up persistent state
- verify migration compatibility
- stop or place risky enforcement in a safe documented mode
- deploy the new version
- run migrations
- verify health/audit status
- run smoke tests

## Rollback

Application rollback must account for database migration compatibility. A release that cannot safely run against the upgraded schema must state that clearly and provide restore instructions.

## Uninstall/data removal

The final installer must distinguish removing application containers/images from deleting persistent security data. Destructive data removal requires an explicit command and warning.

## Future deployment models

Later releases may document hardened bare-metal, systemd, Kubernetes, and distributed deployments. Those are not Phase 1 support targets.
