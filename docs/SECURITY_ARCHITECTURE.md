# Security Architecture

## Security posture

PrivaShield is itself a security control, so compromise of the platform can be worse than ordinary application compromise. Privilege separation, explicit trust boundaries, secure defaults, and verifiable operations are architectural requirements.

## Runtime privilege separation

### Unprivileged services
The dashboard, API, AI worker, database client logic, and most detectors should run without root and without Linux network-administration capabilities.

### Sensor privilege
Packet capture may require narrowly scoped capabilities such as `CAP_NET_RAW` or `CAP_NET_ADMIN` depending on implementation. Prefer dedicated sensor processes or containers with only the capabilities needed.

### Enforcement privilege
Future firewall/eBPF/nftables adapters run as a separate service with the smallest effective capability set. The API must never construct arbitrary shell commands for that service.

## Authorization model

PrivaShield implements five server-side local RBAC roles:

- viewer: read ordinary operational state and telemetry
- analyst: investigate alerts, run analysis, and submit analyst feedback
- operator: perform bounded control-plane mutations, sensor ingestion, simulation workflows, and signed-policy lifecycle operations
- administrator: manage local principals plus all operator functions and audit access
- auditor: inspect audit state, policy history, and operational evidence without mutation authority

Authorization is enforced by API middleware for HTTP and WebSocket routes. UI hiding is not authorization.

The centralized role policy is fail-closed for authenticated mode: unknown protected API routes require at least read authority, and unknown mutations require operator authority.

## Authentication

Two modes exist:

- `disabled`: loopback-oriented development compatibility; actions are explicitly unverified
- `local`: high-entropy bearer authentication with persistent local principals and server-side RBAC

Local bearer tokens are generated from cryptographically secure randomness. Only SHA-256 token digests and short display prefixes are persisted. Raw tokens are returned once at creation or rotation and must be stored by the operator.

A separately configured bootstrap administrator token can create initial durable administrators. It should be removed after durable administrator credentials are verified. Durable administrators cannot disable their own active principal, and when no bootstrap token exists the last enabled durable administrator cannot be disabled.

Browser WebSocket authentication uses a bearer credential in the `Sec-WebSocket-Protocol` request header and selects only the safe `privashield` subprotocol in the response. Tokens are not placed in WebSocket query strings. Proxy/access logging must redact both authorization and WebSocket protocol headers.

External OIDC/SAML integration is not implemented yet. See `docs/AUTHENTICATION.md`.

## Verified audit attribution

When local authentication is enabled, human actor identity comes from the authenticated principal, not a caller-supplied request field. Audit actor strings include the durable principal UUID. Policy lifecycle history also records whether the actor credential was verified.

Legacy `disabled` mode remains explicitly unverified and exists only for local development compatibility.

## Secrets

- Never commit secrets.
- Prefer Docker secrets, mounted files, OS key stores, or dedicated secret managers over plaintext environment variables for hardened deployments.
- Secrets are write-only through management interfaces and never returned through normal GET endpoints.
- Logs must redact known secret fields.
- Never log bearer tokens, bootstrap tokens, `Authorization`, or credential-bearing WebSocket protocol headers.
- Rotate credentials after suspected disclosure.

## Network exposure

Default Compose bindings should remain on localhost unless the deployment documentation explicitly requires otherwise. PostgreSQL, NATS, model runtime, and future privileged adapters should not be exposed to untrusted networks.

Local RBAC is required before PrivaShield should be intentionally exposed beyond loopback. Authentication does not replace TLS or network segmentation.

## TLS

Loopback-only development can operate without TLS. Remote or multi-host deployments require TLS. WAF/TLS interception functionality must document certificate ownership, key storage, trust installation, and privacy implications.

## Input validation

All external data is hostile:

- enforce request body limits
- validate enums/ranges/types
- canonicalize IP/CIDR inputs
- reject path traversal
- avoid dynamic shell execution
- enforce parser limits
- use parameterized database access
- sanitize/encode data before browser rendering

## Policy safety

- Policies are versioned.
- Policy envelopes are authenticated with Ed25519 signatures.
- The running API stores only the policy verification public key, not the offline private signing key.
- Active revisions are immutable.
- Policy approval requires a second operator identity.
- New policy activation creates audit and policy-history records.
- Rollback targets a known previously approved revision, not reconstructed state.
- Current activation is simulation-governance-only and cannot enable privileged execution.

## Kill switch

The kill switch is a deterministic control independent of the AI layer. It must be able to disable active enforcement or invoke a documented isolation mode without waiting for a model response.

Because "kill switch" can mean opposite things, implementations must expose separately named actions such as:

- `disable_enforcement`
- `isolate_interface`
- `restore_last_known_good_policy`

The UI must not collapse these into an ambiguous single action.

No privileged kill switch is implemented in the current release line because privileged enforcement remains gated.

## Cryptography

Audit chaining uses SHA-256 over canonical records plus the previous record hash. Signed policy governance uses Ed25519 over canonicalized policy envelopes with SHA-256 content digests. Cryptographic algorithms and serialization formats are versioned.

Cryptography is not used to conceal architectural weaknesses. Standard libraries and well-reviewed primitives are required.

## Logging

Operational logs and audit logs are separate concepts.

Operational logs may rotate and be redacted. Audit records are append-only domain evidence with integrity linkage.

Never log:

- passwords
- bearer/API tokens
- bootstrap tokens
- private keys
- full authorization headers
- credential-bearing WebSocket protocol headers
- arbitrary raw packet payloads
- full model prompts containing sensitive evidence by default

## Secure failure behavior

Authentication in `local` mode fails closed: missing, invalid, rotated, or disabled bearer credentials receive 401, and authenticated principals without the required role receive 403.

Every future enforcement adapter must separately document whether it fails open, fails closed, or preserves current state for each failure category. There is no universal enforcement default because a fail-closed network control can itself cause a severe outage.

## Hardening before production-ready status

Implemented foundations now include an authenticated local control plane, server-side RBAC, signed/versioned policy, security scanning, and verified local audit attribution. A production-ready label still requires at least:

- hardened secret delivery rather than plaintext environment values
- protected network bindings and TLS for remote deployments
- external identity integration where organizational policy requires it
- SBOM and artifact integrity
- tested backup/restore
- tested enforcement rollback before any privileged enforcement exists
- parser fuzzing or equivalent negative testing
- documented incident-response process
- no unresolved critical/high vulnerabilities affecting the release
