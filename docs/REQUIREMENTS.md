# Requirements

## 1. Functional requirements

### FR-001 Event ingestion
The system shall accept normalized and adapter-specific security events from local sensors and supported integrations.

### FR-002 Event normalization
The system shall normalize source telemetry into a canonical event envelope with source, type, timestamps, severity, subject, network context, evidence references, and processing metadata.

### FR-003 Sensitive-data classification
The system shall classify supported content for PII, PHI, financial data, credentials, secrets, and configurable custom categories. AI classifications shall include confidence, evidence location, model/rule provenance, and policy outcome.

### FR-004 Threat interpretation
The system shall produce analyst-readable summaries of selected events and alerts using a local model. Summaries shall preserve links to source evidence and identify uncertainty.

### FR-005 Malware/ransomware telemetry
The system shall support file-system behavior events including rapid modification, rename, deletion, entropy change, extension change, and process correlation. Active blocking is not an MVP requirement.

### FR-006 User/entity anomaly detection
The system shall support anomaly signals such as impossible travel, unusual access time, abnormal data volume, rapid downloads, and repeated authentication failures when the necessary source data is available.

### FR-007 Network analysis
The system shall capture or ingest packet/flow metadata and extract bounded features such as addresses, ports, protocol, direction, packet length, timing, connection state, and selected protocol metadata.

### FR-008 Firewall decision abstraction
The system shall expose an enforcement decision contract supporting `allow`, `alert`, `drop`, `rate_limit`, `quarantine`, and `redact`, while Phase 1 defaults to observe-only.

### FR-009 WAF integration
The system shall support a reverse-proxy/WAF adapter capable of receiving HTTP request metadata and returning policy decisions. TLS termination and certificate management must be explicit deployment choices.

### FR-010 SOAR action model
The system shall model response actions with requested, approved, executing, succeeded, failed, rolled_back, and rejected states. High-impact actions require authorization and policy gates.

### FR-011 DLP
The system shall inspect supported outbound content and produce detect, redact, block, or allow recommendations according to configured policy and user/context attributes.

### FR-012 Audit logging
Security decisions, configuration changes, privileged actions, policy changes, model changes, and analyst actions shall generate append-only audit events linked by cryptographic hashes.

### FR-013 Dashboard
The local dashboard shall provide system status, event feed, alerts, classifications, AI summaries, firewall mode, policy configuration, monitored sources, model status, and audit verification status.

### FR-014 Local configuration
Authorized operators shall be able to configure monitored local directories, supported network interfaces, detection thresholds, model settings, retention, and operating mode.

### FR-015 Health and readiness
Every service shall expose health/readiness information sufficient for orchestration and the dashboard.

## 2. Non-functional requirements

### NFR-001 Local-first privacy
No telemetry, packet content, prompts, model inputs, audit records, or sensitive classifications may leave the host by default.

### NFR-002 Performance isolation
LLM inference shall not execute synchronously in the inline packet fast path.

### NFR-003 Availability
Failure of optional AI enrichment shall not stop deterministic telemetry ingestion or policy evaluation.

### NFR-004 Bounded enforcement latency
Future inline enforcement components shall have explicit latency budgets, timeout behavior, and fail mode independent of model inference.

### NFR-005 Least privilege
Services shall run without root unless a narrowly scoped capability is technically required. Privileged adapters shall be isolated from the general API and UI processes.

### NFR-006 Data minimization
Packet payload storage shall be disabled by default. Evidence should reference bounded excerpts or hashes where full retention is unnecessary.

### NFR-007 Explainability
Every block, quarantine, redaction, or high-severity alert shall expose rule/model provenance and the evidence used to reach the decision to the extent technically possible.

### NFR-008 Auditability
All material control-plane and enforcement changes shall be attributable to an actor and timestamped.

### NFR-009 Portability
The Phase 1 reference deployment shall run through Docker Compose on a modern Linux host. Development on macOS/Windows may be supported for non-privileged components, but packet enforcement is platform-specific.

### NFR-010 Extensibility
Sensors, classifiers, model runtimes, policy engines, WAFs, and enforcement backends shall use documented interfaces rather than hard-coded coupling.

### NFR-011 Secure supply chain
Production-ready releases shall include dependency scanning, secret scanning, container scanning, SBOMs, checksums/signatures, and provenance where supported.

### NFR-012 Backward compatibility
Stable API versions and persisted schemas shall follow documented migration and deprecation rules.

## 3. Phase 1 acceptance criteria

Phase 1 is complete when a single-machine installation can:

1. start via Docker Compose
2. expose a healthy FastAPI control plane
3. persist canonical events and alerts in PostgreSQL
4. use Redis Streams for internal event transport
5. ingest simulated and at least one real local telemetry source
6. stream events to a local dashboard
7. invoke a local model adapter for classification or threat summarization
8. manage observe-only policies and system configuration
9. produce and verify a hash-chained audit log
10. operate with AI unavailable without losing core event ingestion
11. pass defined unit and integration tests
12. document uninstall and data-removal procedures

## 4. Explicit Phase 1 exclusions

Phase 1 shall not automatically alter kernel firewall state, revoke credentials, terminate sessions, quarantine hosts, or block traffic by default. Those capabilities require later validation and explicit activation.
