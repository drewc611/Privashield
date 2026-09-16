# Deployment

## Reference deployment

The current supported development/MVP topology is one Linux host using Docker Compose.

Services:

- `api`: FastAPI control plane
- `dashboard`: static local security console served through Nginx
- `postgres`: durable events, analyst feedback, signed policy governance, and local principals
- `nats`: JetStream event transport
- `ollama`: optional local model runtime
- `waf`: Coraza + Caddy reverse proxy with OWASP CRS
- `suricata` / `zeek`: optional Linux network-sensor profile
- `suricata-collector` / `zeek-collector`: normalizers and API forwarders
- `file-monitor`: optional read-only host filesystem monitoring profile

Privileged enforcement is not part of this topology.

## Network exposure

Compose publishes the API and WAF/dashboard on loopback by default. PostgreSQL, NATS, Ollama, and sensor-internal services are not published to untrusted interfaces.

Loopback-only development may use `PRIVASHIELD_AUTH_MODE=disabled`. Before intentional non-loopback or multi-user exposure, enable local authentication and deploy TLS/appropriate network controls. Local RBAC does not replace TLS.

## Local authentication bootstrap

Set a high-entropy bootstrap secret through your deployment secret mechanism:

```text
PRIVASHIELD_AUTH_MODE=local
PRIVASHIELD_BOOTSTRAP_ADMIN_TOKEN=<secret>
```

Then:

1. Start or restart the API.
2. Authenticate with the bootstrap token.
3. Create at least two durable `administrator` principals through `POST /api/v1/principals`.
4. Secure their one-time returned tokens.
5. Create a dedicated `operator` principal for sensors/collectors if those profiles are enabled.
6. Set that collector token as `PRIVASHIELD_API_TOKEN` through the secret mechanism.
7. Remove the bootstrap token and restart only after durable administrator credentials have been verified.

Do not use the bootstrap administrator token as the long-lived collector credential.

The dashboard's token input stores the bearer token in browser `sessionStorage` only. Closing the browser session or pressing **Clear** removes it from that browser session.

See `docs/AUTHENTICATION.md` for role boundaries and token lifecycle.

## Signed policy verification

The running API receives only the Ed25519 public verification key:

```text
PRIVASHIELD_POLICY_VERIFICATION_PUBLIC_KEY=<base64-raw-public-key>
PRIVASHIELD_POLICY_VERIFICATION_KEY_ID=local-v1
```

Keep the private signing key offline/operator-side. Do not place it in API or Compose configuration.

## Persistent data

Persist at least:

- PostgreSQL data
- NATS JetStream state where event durability is required
- tamper-evident audit JSONL data
- approved local model files/cache as needed
- operator-managed secrets outside the repository
- optional WAF audit logs/evidence according to retention policy

NATS is not the source of truth for durable control-plane history.

## Environment configuration

`.env.example` documents non-secret defaults and names of optional secret variables. It intentionally contains no usable credentials.

For hardened deployments, prefer Docker secrets, mounted secret files, OS key stores, or a dedicated secret manager rather than plaintext `.env` values. If environment variables are used during development, restrict file/process access and rotate them after suspected exposure.

## Startup order

1. PostgreSQL and NATS become healthy.
2. API starts, initializes the current Phase 1 schema, and reports liveness.
3. Dashboard and WAF start.
4. Optional Ollama health is independent of core API readiness.
5. Optional sensors/collectors start after the API is reachable.
6. In local-auth mode, collectors must have a valid operator/admin bearer token before ingestion will succeed.

Explicit Alembic migrations remain a release-hardening item before schema stability is claimed.

## Enabling sensor profiles

Network sensors require Linux host capture capabilities and should be tested on a dedicated host/VM before production-like use.

```text
docker compose --profile network-sensors up -d
```

The host filesystem monitor is opt-in and mounts the configured path read-only:

```text
docker compose --profile host-monitor up -d
```

When local auth is enabled, set `PRIVASHIELD_API_TOKEN` to a dedicated operator principal token before starting either profile.

## Upgrade procedure

Before upgrade:

- read release notes
- back up persistent PostgreSQL/audit state
- verify schema/migration compatibility
- keep privileged enforcement disabled
- deploy the new version
- verify API health and authentication
- verify the audit chain
- verify sensor authentication where enabled
- run the detection regression benchmark and smoke tests

## Rollback

Application rollback must account for database compatibility. A release that cannot safely run against the upgraded schema must state that clearly and provide restore instructions.

Signed policy rollback is a separate simulation-governance feature and must not be confused with application/database rollback or future privileged-enforcement rollback.

## Uninstall/data removal

Uninstall procedures must distinguish removing application containers/images from deleting persistent security data. Destructive data removal requires an explicit command and warning.

## Future deployment models

Hardened bare-metal/systemd, Kubernetes, high-availability, external identity-provider, and distributed deployments are roadmap items. They are not currently qualified support targets.
