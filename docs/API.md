# API Contract

## Conventions

Base path: `/api/v1`

- JSON request/response bodies unless otherwise noted
- UTC timestamps in RFC 3339 format
- bearer authentication when `PRIVASHIELD_AUTH_MODE=local`
- 401 for missing/invalid credentials and 403 for insufficient role authority
- UUID domain identifiers
- server-side RBAC; dashboard visibility is not authorization
- WebSocket for live dashboard updates

## Authentication and principals

### GET `/auth/me`
Returns the authenticated principal context: principal ID where durable, name, role, credential-verification state, and bootstrap state.

### GET `/auth/capabilities`
Returns authentication mode and capability metadata. In `local` mode this endpoint itself requires an authenticated principal.

### GET `/principals`
Administrator only. Lists local principals without token digests or raw tokens.

### POST `/principals`
Administrator only. Creates a local principal and returns a high-entropy bearer token exactly once.

Request:

```json
{
  "name": "soc-operator-01",
  "role": "operator"
}
```

### POST `/principals/{principal_id}/rotate`
Administrator only. Issues a new one-time token and immediately invalidates the previous token.

### POST `/principals/{principal_id}/disable`
Administrator only. Immediately invalidates the principal credential. A durable administrator cannot disable itself; without a configured bootstrap credential, the last enabled durable administrator cannot be disabled.

See `docs/AUTHENTICATION.md`.

## Role summary

- `viewer`: ordinary read access
- `analyst`: investigation and analysis mutations
- `operator`: bounded operational mutations, sensor ingestion, response simulation, and signed policy lifecycle
- `administrator`: principal administration, operator authority, and audit access
- `auditor`: audit/policy evidence reads without operational mutation

The exact route matrix is enforced by the API authorization middleware.

## Health and status

### GET `/health`
Public liveness check. This is intentionally available without credentials.

### GET `/system/status`
Returns local component and enforcement-mode state. Authenticated in local mode.

## Events

### POST `/events/ingest`
Operator or administrator. Ingests a canonical `SecurityEvent`. Internal collectors use this endpoint.

### GET `/events`
Returns recent canonical events with supported filters/pagination.

### GET `/events/stats`
Returns aggregate severity/source counts.

### GET `/events/{event_id}`
Returns one canonical event.

## Sensors

### POST `/sensors/heartbeat`
Operator or administrator. Registers/refreshes sensor health.

### GET `/sensors`
Returns registered sensor health state.

Internal Suricata/Zeek collectors and the file monitor may send `PRIVASHIELD_API_TOKEN` as a bearer token when local auth is enabled.

## AI and detection endpoints

The local AI layer is advisory only and has no enforcement authority.

Implemented analysis/detection route groups include:

- `/ai`
- `/dlp`
- `/anomaly`
- `/ransomware`
- `/malware`
- `/incidents`

Read operations are available to authenticated readers where applicable. Mutating/evaluation operations require analyst, operator, or administrator authority.

## Analyst feedback

### POST `/feedback`
Analyst, operator, or administrator. Creates an analyst label. In local-auth mode `identity_verified=true` is derived from the authenticated principal, not request content.

### GET `/feedback`
Analyst, operator, administrator, or auditor. Lists feedback.

### GET `/feedback/stats`
Returns feedback distribution statistics.

## Firewall simulation

### GET `/firewall/config`
Returns the observe/simulate configuration.

### PATCH `/firewall/config`
Operator or administrator. Updates simulation configuration and records verified audit attribution when local auth is enabled.

### POST `/firewall/evaluate`
Operator or administrator. Produces a deterministic simulated allow/drop decision. It does not mutate host or network state.

## Response orchestration

### GET `/response/capabilities`
Returns supported simulated response types and `privileged_execution=false`.

### POST `/response/actions`
Operator or administrator. Creates a pending simulated response action. `requested_by` is derived from the authenticated principal when local auth is enabled.

### GET `/response/actions`
Returns response actions.

### POST `/response/actions/{action_id}/approve`
Operator or administrator. Approves a pending action. In local-auth mode caller-supplied `approved_by` text cannot override the verified principal identity.

### POST `/response/actions/{action_id}/simulate`
Operator or administrator. Executes simulation only. No privileged host/network mutation occurs.

### POST `/response/actions/{action_id}/cancel`
Operator or administrator. Cancels a pending/approved simulated action.

## Signed policies

Signed policy governance is simulation-only. The running API stores only an Ed25519 public verification key and cannot sign policy content.

In local-auth mode human actor identity is derived from the verified principal. Legacy body actor strings are used only in explicitly unverified development mode.

### GET `/policies/capabilities`
Returns verification configuration, configured key ID, algorithm, mandatory approval state, and `privileged_execution=false`.

### POST `/policies/revisions`
Operator or administrator. Registers an already signed policy revision after Ed25519 verification. Revisions increase monotonically.

### GET `/policies/{policy_id}/revisions`
Operator, administrator, or auditor. Lists revisions newest first.

### GET `/policies/{policy_id}/revisions/{version}`
Returns one stored revision.

### POST `/policies/{policy_id}/revisions/{version}/approve`
Operator or administrator. Requires a second actor and re-verifies signature/digest before approval.

### POST `/policies/{policy_id}/revisions/{version}/activate`
Operator or administrator. Activates an approved revision for simulation governance only.

### GET `/policies/{policy_id}/active`
Returns the active simulation-governance revision, if any.

### GET `/policies/{policy_id}/history`
Returns append-only registration, approval, activation, supersession, and rollback history with identity-verification metadata.

### POST `/policies/{policy_id}/rollback`
Operator or administrator. Selects a previously approved older revision after signature/digest verification. This is policy revision rollback, not privileged-enforcement rollback qualification.

See `docs/POLICY_GOVERNANCE.md`.

## Audit

### GET `/audit`
Auditor or administrator. Returns recent tamper-evident audit entries.

### GET `/audit/verify`
Auditor or administrator. Verifies the local hash chain without repairing or rewriting it.

Human audit actors use authenticated principal identity when local auth is enabled. Engine-generated records remain attributed to their engine/service identity.

## Live WebSocket

### WS `/ws/events`
Streams local security events to authenticated readers.

Non-browser clients may send `Authorization: Bearer <token>`. Browser clients use subprotocols:

```text
privashield
privashield.bearer.<token>
```

The server selects only `privashield`. Do not log credential-bearing `Sec-WebSocket-Protocol` request headers.

## Development compatibility

With `PRIVASHIELD_AUTH_MODE=disabled`, the API preserves loopback development behavior and labels the request context `local-development-unverified`. This mode is not suitable for intentional remote or multi-user exposure.

## API evolution

Breaking changes require a versioned API or documented migration. Removing stable fields requires a deprecation window after the project reaches stable releases.
