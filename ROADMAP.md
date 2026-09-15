# PrivaShield Roadmap

This roadmap is capability-oriented. Dates are intentionally omitted until release qualification and sustained test/operational evidence justify them.

A checked item means the capability exists in the repository. It does **not** imply production certification or authorization for privileged enforcement.

## Foundation and local MVP

- [x] Project governance and documentation foundation
- [x] Canonical `SecurityEvent` contract
- [x] FastAPI control plane
- [x] PostgreSQL persistence
- [x] NATS JetStream event publishing
- [x] WebSocket live-event feed
- [x] Ollama-compatible local AI analysis
- [x] Sensor heartbeat/health registry
- [x] Tamper-evident audit-chain implementation
- [x] Docker Compose self-hosted stack
- [x] Local operator dashboard
- [x] Loopback-only reverse-proxy publishing
- [x] Suricata EVE normalization
- [x] Zeek JSON normalization
- [x] Passive live Suricata and Zeek sensor profile

## Detection and privacy intelligence

- [x] Local DLP classification
- [x] PII, PHI-context, financial, payment-card, and credential pattern detection
- [x] Permission-tier redaction
- [x] Identity anomaly scoring
- [x] Impossible-travel detection signal
- [x] Rapid-download detection signal
- [x] Ransomware behavior scoring
- [x] File-risk scoring
- [x] Read-only host filesystem monitor
- [ ] Cross-sensor incident correlation
- [ ] Analyst feedback and labeling loop
- [ ] Detection evaluation corpus and benchmark harness
- [ ] Model/rule quality metrics and regression thresholds

## Perimeter and response orchestration

- [x] Coraza + Caddy WAF profile
- [x] OWASP Core Rule Set integration
- [x] WAF JSON audit logging
- [x] Firewall allow/drop simulation
- [x] Approval-gated response-action state machine
- [x] Simulated block-IP workflow
- [x] Simulated interface-isolation workflow
- [x] Simulated session-termination workflow
- [x] Simulated token-revocation workflow
- [x] Simulated file-quarantine workflow
- [x] Simulated process-stop workflow
- [x] Explicit `privileged_execution=false` capability boundary
- [ ] Deterministic signed policy model
- [ ] Policy versioning and approval history
- [ ] Kill-switch and rollback qualification for future enforcement

## Security and software assurance

- [x] CI lint and test gates
- [x] Docker Compose validation
- [x] Dashboard JavaScript syntax validation
- [x] CodeQL workflow
- [x] Pull-request dependency review
- [x] Dependabot configuration
- [x] Shared AI-agent safety harness
- [x] Specialized project agents
- [ ] SBOM generation in CI
- [ ] Build provenance / artifact attestation
- [ ] Signed release artifacts
- [ ] Automated secret-scanning policy validation
- [ ] End-to-end security regression suite

## Operator and enterprise hardening

- [ ] Role-based access control
- [ ] External identity provider integration
- [ ] Multi-user audit attribution
- [ ] Retention-policy controls
- [ ] Backup/restore qualification
- [ ] SIEM export connectors
- [ ] High-availability deployment pattern
- [ ] Performance/load characterization
- [ ] Resilience and failure-injection testing
- [ ] Upgrade/migration qualification

## Future privileged enforcement

The following work is intentionally gated. None of it should be considered active merely because simulation/orchestration exists.

- [ ] Dedicated privileged enforcement service
- [ ] eBPF/XDP data plane
- [ ] nftables adapter
- [ ] network/session quarantine execution
- [ ] process containment execution
- [ ] credential/session revocation adapters
- [ ] deterministic rollback and recovery controller
- [ ] signed policy approval required before enforcement
- [ ] explicit production kill switch

Privileged enforcement cannot be enabled by AI output. It requires a separately reviewed deterministic data plane, human-approved architecture change, rollback controls, tests, and operational qualification.

## Packaging and ecosystem

- [ ] First signed pre-release
- [ ] Versioned installation bundles
- [ ] Desktop/local wrapper evaluation
- [ ] Plugin SDK
- [ ] External telemetry adapter SDK
- [ ] Rule/model packs
- [ ] Documented third-party integration contracts

Roadmap items move only when their security, privacy, performance, failure-mode, and rollback criteria are defined and testable.
