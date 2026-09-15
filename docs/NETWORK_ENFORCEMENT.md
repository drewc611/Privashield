# Network Sensing and Enforcement

## Purpose

PrivaShield separates observation from enforcement so packet capture, feature extraction, AI analysis, policy, and privileged network mutation can evolve independently.

## Operating modes

### Observe
Collect telemetry and produce findings/decisions without changing traffic.

### Alert
Observe plus analyst-visible alerts and notifications. No traffic mutation.

### Enforce
Apply approved deterministic decisions through a privileged backend. Not enabled in Phase 1.

### Isolation
A narrowly defined emergency mode that blocks or restricts selected interfaces, hosts, sessions, or destinations according to a preconfigured profile. Isolation is not synonymous with disabling enforcement.

## Sensor pipeline

The initial network sensor should extract bounded metadata such as:

- timestamp
- interface
- source/destination IP and port
- L3/L4 protocol
- packet/frame length
- flow direction
- connection/flow identifier
- TCP flag/state metadata
- bounded DNS/TLS/HTTP metadata where parsers support it
- timing and rate features

Raw payload capture remains off by default.

## Deep packet inspection

DPI is opt-in and protocol-scoped. Parsers operate under strict size, time, and recursion limits. Encrypted traffic is not transparently decrypted. TLS interception, if ever provided, is a separate explicitly configured capability with certificate/privacy documentation.

## Fast path

The future inline path must use deterministic, bounded mechanisms such as compiled policy, efficient feature classifiers, WAF rules, or eBPF/XDP/nftables primitives. LLM inference is never synchronous in the packet fast path.

## Enforcement contract

A validated enforcement request contains:

- action type
- canonical target
- source decision ID
- policy revision
- reason codes
- TTL/expiry when supported
- requesting actor/service
- idempotency key
- rollback metadata

The adapter rejects unknown action types, malformed targets, unsupported capabilities, expired requests, and policy mismatches.

## Candidate backends

- nftables for modern Linux host firewall control
- eBPF/XDP for high-performance Linux telemetry and carefully bounded enforcement
- reverse-proxy/WAF adapter for HTTP/S controls
- iptables only where required for compatibility

The domain model must not depend on backend-specific command syntax.

## Failure behavior

Fail behavior is explicit per deployment and action type:

- `preserve_state`: keep currently applied rule state
- `fail_open`: permit traffic when decision service is unavailable
- `fail_closed`: deny traffic when decision service is unavailable

No backend silently selects a fail mode. Production enablement requires outage simulation and recovery tests.

## Rule lifecycle

Rules have stable identifiers, policy provenance, timestamps, optional expiry, and reconciliation state. The adapter periodically compares desired state with applied state and reports drift.

## Rollback

Before high-impact changes, the system records sufficient previous state to restore a known-good configuration. Rollback must be idempotent and separately audited.

## Kill-switch controls

Expose distinct controls:

- stop new enforcement decisions
- remove temporary PrivaShield-applied rules
- restore last known good ruleset
- isolate selected interface/target using a predefined emergency profile

These operations require strong authorization and prominent confirmation in the UI when they can disrupt connectivity.

## Phase 1 constraint

Phase 1 network functionality is observe-only. The codebase may define enforcement interfaces and mocks, but no default path may modify host firewall state.
