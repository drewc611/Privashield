# PrivaShield

PrivaShield is an open-source, self-hosted security platform focused on local-first AI-assisted threat detection, privacy protection, network analysis, inline filtering, data-loss prevention, and auditable response automation.

The project is being built iteratively using a documented Software Development Lifecycle. The architecture deliberately separates deterministic enforcement from AI reasoning. Inline packet and request decisions must remain fast, bounded, reversible, and observable. Local AI models enrich alerts, classify sensitive data, explain threats, and recommend remediation without becoming an uncontrolled dependency in the packet fast path.

## Planned capabilities

- Sensitive-data classification for PII, PHI, financial information, secrets, and credentials
- AI-assisted threat interpretation for network, endpoint, SIEM, and ransomware telemetry
- Malware and ransomware behavior detection
- User and entity anomaly detection
- Network telemetry and deep packet metadata analysis
- Inline AI-assisted firewall policy enforcement
- Reverse-proxy/WAF integration
- Automated containment and quarantine workflows
- Smart DLP and policy-based redaction
- Tamper-evident cryptographic audit logging
- Local real-time dashboard and analyst control plane
- Local model support through pluggable runtimes such as Ollama

## Phase 1 target

The first milestone is a single-machine MVP that can ingest normalized security events, persist and stream them, classify and summarize selected events with a local model, expose policy and health APIs, and render a local dashboard. Active packet dropping, quarantine, destructive response actions, and autonomous remediation remain disabled until later phases and require explicit policy gates.

## Architecture at a glance

- **Control plane:** Python, FastAPI, Pydantic
- **Event processing:** Redis Streams initially, with an abstraction for later Kafka/NATS support
- **Persistence:** PostgreSQL
- **AI runtime:** local model adapter, initially Ollama-compatible
- **Network sensors:** pluggable adapters for libpcap/Scapy and later eBPF/XDP
- **Policy/enforcement:** separate bounded enforcement service, initially observe-only
- **UI:** React/Next.js local dashboard
- **Packaging:** Docker Compose first, then signed release artifacts

## Documentation

Start with:

- `docs/REQUIREMENTS.md`
- `docs/ARCHITECTURE.md`
- `docs/MVP.md`
- `docs/API.md`
- `docs/DATA_MODEL.md`
- `docs/THREAT_MODEL.md`
- `docs/SECURITY_ARCHITECTURE.md`
- `docs/SDLC.md`
- `docs/DEVELOPMENT.md`
- `docs/DEPLOYMENT.md`
- `docs/OPERATIONS.md`
- `docs/TESTING.md`
- `ROADMAP.md`

## Project status

**Status:** pre-alpha / architecture and project-foundation phase.

Do not deploy PrivaShield as a production enforcement control until the relevant component is explicitly marked production-ready and its security, performance, rollback, and failure-mode tests have passed.

## Contributing

Read `CONTRIBUTING.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md` before contributing.

## License

Apache License 2.0. See `LICENSE`.
