# Glossary

## Alert
An analyst-facing security case created from one or more events/findings and tracked through an investigation lifecycle.

## Analysis job
An asynchronous request for AI-assisted classification, summarization, remediation assistance, or analyst Q&A.

## Audit record
An immutable, hash-chained record of a material security or administrative action.

## Classification
A determination that content belongs to a sensitive-data category such as PII, PHI, financial data, credentials, or secrets.

## Decision
A deterministic policy outcome such as observe, alert, allow, drop, redact, rate-limit, or quarantine. Phase 1 only permits non-destructive effective outcomes.

## Enforcement adapter
A privileged, isolated component that translates validated decisions into a specific security control such as nftables, eBPF/XDP, or a reverse proxy.

## Event
Normalized source telemetry representing something observed by a sensor or integration.

## Evidence reference
A bounded pointer and integrity hash for source material used by an alert, finding, classification, or analysis without unnecessarily duplicating the full content.

## Finding
A detector-generated observation attached to one or more events. Multiple findings may be promoted or correlated into an alert.

## Local-first
The default architectural policy that telemetry storage, processing, and AI inference stay on the operator-controlled host/environment unless an external integration is explicitly enabled.

## Model run
An immutable provenance record describing a single AI inference operation, including provider/model identity, prompt-template version, evidence references, parameters, and output validation state.

## Observe mode
Telemetry and decisions are generated, but PrivaShield does not mutate traffic, sessions, credentials, or endpoint state.

## Policy bundle
A versioned set of deterministic rules and operating mode settings used to derive decisions.

## Sensor
A process or adapter that collects telemetry from a network interface, file system, identity source, reverse proxy, log stream, or simulator.

## Threat analysis
A structured, AI-assisted interpretation of security evidence. It is advisory until deterministic policy and authorization convert a recommendation into an approved action.

## WAF
Web Application Firewall. In PrivaShield this refers to a reverse-proxy or integrated HTTP request filtering layer, distinct from raw network packet filtering.
