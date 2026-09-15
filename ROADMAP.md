# Roadmap

This roadmap is capability-oriented. Dates are intentionally omitted until implementation velocity and test coverage are known.

## Phase 1. Requirements and MVP architecture

- project governance and documentation
- normalized event, alert, classification, policy, action, audit, and system-state models
- FastAPI control plane
- PostgreSQL persistence
- Redis Streams event transport
- local model adapter with Ollama-compatible implementation
- observe-only network sensor adapter
- local React/Next.js dashboard shell
- Docker Compose single-machine deployment
- health, metrics, event feed, classification, summarization, policy, and configuration APIs
- tamper-evident audit-chain prototype

## Phase 2. Detection foundation

- packet/flow feature extraction
- signature/rule adapter support
- anomaly scoring framework
- sensitive-data classification pipeline
- endpoint/file-system event ingestion
- ransomware behavior heuristics
- analyst feedback and labeling loop
- detection evaluation harness

## Phase 3. Controlled enforcement

- policy engine
- bounded firewall decision service
- eBPF/nftables/iptables adapters as platform permits
- reverse-proxy/WAF integration
- explicit observe, alert, block, quarantine modes
- kill switch and deterministic rollback
- policy signing and approval flow

## Phase 4. DLP and SOAR

- outbound content inspection
- redaction/masking actions
- scoped session and identity isolation adapters
- credential-revocation integrations
- playbooks with authorization and rollback
- approval gates for high-impact actions

## Phase 5. Enterprise hardening

- role-based access control
- external identity providers
- HA deployment patterns
- signed releases and provenance
- SBOM and dependency attestation
- expanded observability and SIEM export
- retention controls and backup/restore
- performance and resilience qualification

## Phase 6. Ecosystem

- plugin SDK
- rule/model packs
- external telemetry adapters
- documented integration contracts
- packaged desktop/local installer options

Roadmap items move only when their security, privacy, performance, failure-mode, and rollback criteria are defined and testable.
