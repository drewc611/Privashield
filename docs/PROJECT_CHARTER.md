# Project Charter

## Mission

Build an open-source, self-hosted security platform that helps individuals and organizations detect, understand, and contain privacy and cyber threats while keeping security telemetry and AI inference local by default.

## Problem statement

Security teams commonly operate fragmented tools for network telemetry, sensitive-data discovery, endpoint events, threat interpretation, WAF controls, DLP, and response automation. PrivaShield aims to provide a coherent local control plane that normalizes those signals, applies deterministic policy, uses local AI for analysis and classification, and records security decisions in a verifiable audit trail.

## Primary users

- security analysts and incident responders
- privacy and compliance teams
- developers and platform engineers operating self-hosted systems
- small organizations that need a local security stack without a mandatory cloud dependency
- advanced individual users running local infrastructure

## Project principles

1. **Local first.** Security data and model inference remain local unless an administrator explicitly configures an external integration.
2. **Deterministic enforcement.** AI can enrich and recommend. Privileged enforcement occurs through bounded policy-controlled actions.
3. **Least privilege.** Sensors and services receive only the privileges required for their role.
4. **Data minimization.** Collect the least sensitive telemetry needed to achieve the detection objective.
5. **Observable and reversible.** Every enforcement action must be attributable, logged, and recoverable where technically possible.
6. **Secure by default.** Unsafe modes require explicit activation and clear operator warnings.
7. **Open interfaces.** Core contracts are documented so sensors, models, rules, and response adapters can be replaced.
8. **Evidence over claims.** Detection accuracy, performance, and security claims require repeatable tests.

## In scope

- security event ingestion and normalization
- network telemetry and packet/flow feature extraction
- sensitive-data classification
- AI-assisted threat summaries and analyst Q&A
- anomaly and behavior detection
- file-system ransomware indicators
- WAF and firewall policy integration
- DLP inspection and redaction workflows
- containment and quarantine adapters
- cryptographic audit logging
- local dashboard and control plane
- Docker-based single-node deployment, followed by hardened multi-node patterns

## Out of scope for the initial MVP

- autonomous unrestricted remediation
- opaque remote telemetry or mandatory SaaS services
- replacing enterprise SIEM/SOAR products in Phase 1
- claiming zero-day detection without validated evidence
- TLS interception without explicit administrator configuration and documented certificate handling
- kernel-level enforcement before the observe-only pipeline is stable and tested

## Success criteria

The project is successful when a user can install it locally, ingest supported telemetry, see normalized security events in real time, run local AI classification and threat interpretation, control policy safely, verify audit history, and later activate tested enforcement modules with predictable failure and rollback behavior.

## Governance

Project governance is defined in `../GOVERNANCE.md`. Security reporting is defined in `../SECURITY.md`.
