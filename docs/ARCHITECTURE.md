# Architecture

## 1. Architecture goals

PrivaShield is designed as a local-first security platform with strict separation between telemetry collection, asynchronous AI analysis, deterministic policy, privileged enforcement, storage, and operator control.

The most important architectural rule is that an LLM is never the packet fast path and never receives unrestricted authority to execute privileged actions.

## 2. Logical architecture

```text
+-------------------+      +-----------------------+
| Local Sensors      | ---> | Ingestion / Normalize |
| network/files/auth |      +-----------+-----------+
+-------------------+                  |
                                        v
                              +---------+---------+
                              | Event Bus         |
                              | Redis Streams     |
                              +----+---------+----+
                                   |         |
                         +---------+         +----------------+
                         v                                   v
                +--------+---------+                  +------+-------+
                | Detection /      |                  | Persistence  |
                | AI Enrichment    |                  | PostgreSQL   |
                +--------+---------+                  +------+-------+
                         |                                   |
                         v                                   |
                +--------+---------+                         |
                | Policy / Decision| <-----------------------+
                +--------+---------+
                         |
             observe-only in Phase 1
                         |
                         v
                +--------+---------+
                | Enforcement API  |
                | isolated adapter |
                +------------------+

       +---------------------------------------------+
       | FastAPI Control Plane                       |
       | REST + WebSocket/SSE + auth + config        |
       +----------------------+----------------------+
                              |
                              v
                    +---------+---------+
                    | Local Dashboard   |
                    | React / Next.js    |
                    +-------------------+
```

## 3. Components

### 3.1 Sensor adapters

Sensors collect telemetry from supported sources. Initial adapters should be independently restartable and emit a normalized envelope through the ingestion layer.

Planned sources:

- packet/flow capture using libpcap-compatible tooling or Scapy for prototyping
- eBPF-based network/process telemetry in later Linux phases
- file-system events
- authentication/identity logs
- reverse-proxy/WAF events
- external SIEM/log adapters

Sensors should not own business logic, policy, or AI prompts.

### 3.2 Ingestion and normalization

The ingestion service validates source events, stamps ingestion metadata, converts source-specific fields into canonical models, rejects malformed events, and publishes accepted events to the internal event bus.

### 3.3 Event transport

Phase 1 uses Redis Streams because it is simple to operate on one machine, supports consumer groups, and provides sufficient durability for the MVP. The domain layer must not depend directly on Redis types so a future NATS or Kafka transport can be substituted.

### 3.4 PostgreSQL

PostgreSQL stores canonical events, alerts, classifications, policies, actions, configuration metadata, model runs, and audit-chain records. Large raw artifacts should not be stored indiscriminately in relational rows. Evidence references should use hashes and bounded artifacts when practical.

### 3.5 Detection services

Detection services consume normalized events and produce findings, scores, and alerts. Detection sources may include deterministic rules, statistical models, lightweight ML classifiers, signatures, anomaly models, or local LLM-assisted analysis.

### 3.6 AI enrichment

The AI service runs asynchronously through a model-provider abstraction. The first provider is expected to support an Ollama-compatible local endpoint.

AI responsibilities include:

- sensitive-data classification assistance
- threat-summary generation
- analyst follow-up explanations
- remediation suggestions

AI output must be schema-validated, labeled with model/version/prompt provenance, and treated as advisory unless a deterministic policy explicitly consumes a bounded result.

### 3.7 Policy and decision service

The decision service resolves configured policy using normalized context and detection outputs. It produces a `Decision` object with action, confidence, evidence references, policy version, reason codes, and expiry where relevant.

Phase 1 supports observe/alert behavior only. Later phases may map decisions to firewall, WAF, DLP, session, or quarantine adapters.

### 3.8 Enforcement adapter

Privileged enforcement is isolated from the general API process. The adapter receives only validated, authorized, bounded actions. Future implementations may target nftables, iptables, eBPF/XDP, reverse proxies, endpoint controls, or identity/session systems.

The adapter must expose:

- dry-run/observe mode
- apply operation
- verification operation
- rollback operation
- health state
- capability discovery

### 3.9 Audit service

Every material security decision, policy/configuration change, privileged action, model change, and operator action generates an audit record. Records are canonicalized and hash chained to make later modification detectable.

### 3.10 Control plane

FastAPI exposes versioned APIs for events, alerts, AI analysis, policies, configuration, actions, system health, models, audit verification, and event streaming.

### 3.11 Dashboard

The recommended UI is React with Next.js for a durable application architecture. It runs locally and communicates only with the local API by default.

Primary views:

- overview/system health
- real-time event feed
- alerts and investigations
- data classifications
- firewall/policy control center
- AI threat interpreter
- monitored sources
- audit integrity
- system configuration

## 4. Trust boundaries

### Boundary A: hostile telemetry
All packets, logs, files, HTTP requests, imported alerts, and external metadata are untrusted.

### Boundary B: model boundary
Prompts and retrieved evidence may contain attacker-controlled text. Model output is untrusted and cannot invoke tools directly.

### Boundary C: control plane
The UI/API can change security posture. Authentication, authorization, CSRF protections where applicable, validation, and audit logging are required.

### Boundary D: privileged enforcement
Kernel/network/security-control mutation is the highest-risk boundary and must run in a separate least-privileged process or container with narrowly scoped capabilities.

### Boundary E: persisted evidence
Stored telemetry may contain sensitive or attacker-crafted content. Query, rendering, export, and retention logic must account for this.

## 5. Reference technology stack

- Python 3.12+ for control plane, analysis workers, and initial sensors
- FastAPI and Pydantic for APIs/contracts
- SQLAlchemy/Alembic for persistence and migrations
- PostgreSQL for durable state
- Redis Streams for Phase 1 event transport
- React/Next.js with TypeScript for the dashboard
- Ollama-compatible local model provider
- scikit-learn/ONNX Runtime for lightweight classifiers where appropriate
- libpcap/Scapy initially, with eBPF/XDP for later high-performance Linux telemetry/enforcement
- OpenTelemetry-compatible instrumentation
- Docker Compose for the MVP

## 6. Failure principles

- AI failure must degrade enrichment, not basic ingestion.
- event-bus failure must be visible and backpressure must be bounded.
- database failure must not silently discard security events.
- enforcement timeouts must follow an explicit configured fail policy.
- dashboard failure must not disable backend protection.
- the kill switch must bypass AI and remain deterministic.

## 7. Scaling path

The MVP is a modular monolith plus workers on one machine. Interfaces are chosen so services can later split by responsibility without changing domain contracts. Scale-out should occur only after profiling demonstrates a need.
