# Threat Model

## Method

PrivaShield uses a practical STRIDE-informed threat model supplemented by abuse-case analysis for AI, supply chain, privileged enforcement, privacy, and operational failure.

## Assets

High-value assets include:

- network and endpoint telemetry
- packet metadata and any retained payload evidence
- sensitive-data classifications
- credentials, API keys, model/provider secrets, and signing keys
- firewall/WAF/DLP policy
- response-action authority
- local model inputs and outputs
- audit-chain integrity
- administrator sessions
- software artifacts, container images, and dependency graph

## Adversaries

- remote unauthenticated attacker
- authenticated but compromised user
- malicious insider
- compromised endpoint or sensor
- attacker controlling content inspected by the system
- attacker attempting prompt injection through logs, web requests, documents, or packet payloads
- supply-chain attacker
- local attacker with partial host access
- operator error or unsafe configuration

## Attack surfaces

### Public/local API
Threats: unauthorized access, broken object authorization, injection, request smuggling through proxies, excessive resource use, CSRF where browser sessions apply, credential/session theft.

Controls: loopback-by-default MVP, authentication before remote exposure, RBAC, strict Pydantic validation, rate limits, bounded payloads, secure headers, audit logging, explicit proxy trust configuration.

### Dashboard
Threats: stored/reflected XSS through attacker-controlled logs, unsafe HTML rendering, session theft, accidental disclosure of sensitive evidence.

Controls: render telemetry as data, not trusted HTML; output encoding; CSP; least-privilege views; sensitive-field masking; no model-generated raw HTML execution.

### Sensors/parsers
Threats: malformed packets/files/logs causing crashes or code execution, parser bombs, resource exhaustion.

Controls: bounded parsers, time/size limits, isolation, fuzzing, negative tests, minimal privileges, drop malformed input safely.

### Event bus
Threats: forged events, replay, queue flooding, consumer starvation, unauthorized subscription.

Controls: local/private network, service authentication as deployment evolves, source identity, stable IDs, backpressure limits, consumer groups, telemetry on lag and rejected events.

### PostgreSQL
Threats: SQL injection, credential theft, overprivileged roles, tampering, data exfiltration.

Controls: parameterized ORM/query patterns, separate service credentials where useful, least privilege, local-only binding by default, backups, audit consistency checks.

### Local model runtime
Threats: prompt injection, malicious model files, model supply-chain poisoning, excessive resource consumption, sensitive-data leakage, hallucinated commands/remediation.

Controls: no direct privileged tools, allowlisted provider endpoints, model provenance/digests, bounded context, schema validation, prompt-template versioning, output treated as untrusted, time/token limits, operator visibility.

### Policy engine
Threats: malicious/incorrect rule activation, bypass through ambiguous precedence, unsafe default action, stale policy, tampering.

Controls: versioned immutable active revisions, validation, deterministic precedence, explicit default behavior, audit records, rollback, signed policy bundles in hardened releases.

### Enforcement adapter
Threats: privilege escalation, command injection, denial of service by blocking legitimate traffic, persistence of stale blocks, bypass, fail-open/fail-closed surprises.

Controls: isolated privileged service, structured commands rather than shell strings, capability allowlist, TTLs where appropriate, dry run, verification, rollback, kill switch, explicit failure mode, unit/integration tests using isolated namespaces.

### Audit log
Threats: deletion, truncation, reordering, modification, forged actor attribution.

Controls: monotonic sequence, previous-hash linkage, canonical serialization, periodic verification, external checkpoints/signatures in later phases, restricted write path, backup and export.

### Software supply chain
Threats: dependency compromise, malicious contributor, stolen publishing credentials, image substitution, compromised CI.

Controls: locked dependencies, review, SAST/SCA/secret scanning, SBOM, artifact checksums/signatures, provenance, minimal CI permissions, protected release workflow.

## AI-specific abuse cases

### Prompt injection from telemetry
An attacker embeds instructions in logs, headers, documents, filenames, or request bodies intended to manipulate the local LLM.

Mitigation: clearly separate instructions from evidence, never grant model tool authority, quote/structure evidence, validate outputs, keep deterministic policy independent.

### Model-driven denial of service
Attacker causes expensive analysis on a flood of inputs.

Mitigation: rate limits, event sampling/priority, queue quotas, bounded token/context budgets, asynchronous workers, circuit breakers.

### Hallucinated remediation
Model recommends an unsafe command or incorrect containment action.

Mitigation: recommendations are text/structured advice only. A separate policy/authorization path is required for any executable action.

### Sensitive-data echo
Model output repeats secrets or PII into logs/UI.

Mitigation: output filtering/masking according to viewer role, no verbose prompt logging, policy-controlled retention, redacted operational logs.

## Security invariants

1. No model output directly mutates host/network security state.
2. Phase 1 cannot silently become active enforcement.
3. Every privileged action has an actor, reason, policy context, and audit event.
4. Secrets are not returned through read APIs.
5. Raw packet payloads are not retained by default.
6. An AI outage does not disable deterministic ingestion.
7. A dashboard outage does not disable backend protection.
8. Audit verification never silently repairs evidence of tampering.

## Threat-model maintenance

Update this document when adding a new ingress path, privileged capability, parser, model provider, persistence store, external integration, authentication method, or enforcement backend.
