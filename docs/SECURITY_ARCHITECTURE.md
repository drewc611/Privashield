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

Planned roles:

- viewer: read non-sensitive operational state
- analyst: investigate alerts and request AI analysis
- operator: modify approved operational policy and execute bounded actions
- administrator: manage system configuration, identities, and high-impact settings
- auditor: inspect audit state and exported evidence without operational mutation authority

Every sensitive endpoint must enforce authorization server-side. UI hiding is not authorization.

## Authentication

Phase 1 development may support loopback-only bootstrap access. Remote exposure requires authentication before the project can call that configuration supported.

Future authentication should support local credentials with strong password hashing and external OIDC where appropriate. Session cookies should be Secure/HttpOnly/SameSite when browser sessions are used.

## Secrets

- Never commit secrets.
- Prefer Docker secrets, mounted files, OS key stores, or dedicated secret managers over plaintext environment variables for hardened deployments.
- Secrets are write-only through management interfaces and never returned through normal GET endpoints.
- Logs must redact known secret fields.
- Rotate credentials after suspected disclosure.

## Network exposure

Default Compose bindings should remain on localhost unless the deployment documentation explicitly requires otherwise. PostgreSQL, Redis, model runtime, and privileged adapters should not be exposed to untrusted networks.

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
- Active revisions are immutable.
- Enforcement-capable policies must define default/fallback behavior.
- High-impact actions may require approval based on deployment mode.
- New policy activation creates an audit record.
- Rollback targets a known previous revision, not reconstructed state.

## Kill switch

The kill switch is a deterministic control independent of the AI layer. It must be able to disable active enforcement or invoke a documented isolation mode without waiting for a model response.

Because "kill switch" can mean opposite things, implementations must expose separately named actions such as:

- `disable_enforcement`
- `isolate_interface`
- `restore_last_known_good_policy`

The UI must not collapse these into an ambiguous single action.

## Cryptography

Initial audit chaining uses SHA-256 over canonical records plus the previous record hash. Cryptographic algorithms and serialization formats are versioned. Future releases may add signed checkpoints using a protected signing key.

Cryptography is not used to conceal architectural weaknesses. Standard libraries and well-reviewed primitives are required.

## Logging

Operational logs and audit logs are separate concepts.

Operational logs may rotate and be redacted. Audit records are append-only domain evidence with integrity linkage.

Never log:

- passwords
- API tokens
- private keys
- full authorization headers
- arbitrary raw packet payloads
- full model prompts containing sensitive evidence by default

## Secure failure behavior

Every enforcement adapter documents whether it fails open, fails closed, or preserves current state for each failure category. There is no universal default because a fail-closed network control can itself cause a severe outage.

## Hardening before production-ready status

A production-ready label requires at least:

- authenticated control plane
- server-side RBAC
- secure secret handling
- protected network bindings
- signed/versioned policy
- security scanning in CI
- SBOM and artifact integrity
- tested backup/restore
- tested enforcement rollback
- parser fuzzing or equivalent negative testing
- documented incident-response process
- no unresolved critical/high vulnerabilities affecting the release
