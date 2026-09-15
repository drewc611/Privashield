# ADR-0001: Separate AI reasoning from inline enforcement

- Status: Accepted
- Date: 2026-09-15

## Context

PrivaShield will use local AI models for classification, threat interpretation, correlation, and remediation assistance. Network and WAF enforcement paths have strict latency, availability, and determinism requirements. LLM inference is comparatively slow, resource-intensive, non-deterministic, and vulnerable to attacker-controlled prompt content.

## Decision

LLM inference will not run synchronously in the packet/request fast path and will not directly execute privileged actions.

Inline enforcement will use deterministic policy, bounded feature classifiers, signatures/rules, and platform-native enforcement primitives. AI output may enrich context or propose actions, but any effect on enforcement must pass through a typed decision contract, deterministic policy, authorization, and a privileged adapter.

## Consequences

Benefits:

- bounded enforcement latency
- AI outages do not halt core traffic processing
- prompt injection cannot directly become a privileged command
- policy decisions remain reproducible and auditable
- models can be replaced without redesigning the fast path

Costs:

- some AI-derived detections may affect traffic only after asynchronous analysis
- architecture requires separate analysis and enforcement pipelines
- richer correlation may be advisory rather than immediate

## Alternatives considered

### Put an LLM directly in the request path
Rejected because latency, availability, cost, nondeterminism, and prompt-injection risk are unacceptable for a security fast path.

### Allow the model to call firewall tools directly
Rejected because model output is untrusted and cannot serve as an authorization boundary.
