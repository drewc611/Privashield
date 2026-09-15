# Cryptographic Audit Logging

## Goal

PrivaShield audit records provide tamper evidence for security decisions, policy/configuration changes, privileged actions, model changes, and operator activity. The audit chain is not a replacement for database access controls or backups. It makes unauthorized modification detectable.

## Record design

Each immutable `AuditRecord` includes:

- monotonic sequence number
- record UUID
- occurrence timestamp
- actor type and identifier
- action
- resource type and identifier
- outcome and reason code
- request/correlation identifier
- bounded metadata or metadata hash
- previous record hash
- record hash
- hash/canonicalization version

## Canonicalization

Hashing requires deterministic serialization. Phase 1 should define a canonical JSON representation with:

- stable field names
- stable ordering
- UTF-8 encoding
- explicit null handling
- normalized timestamps
- no non-deterministic whitespace

The canonicalization version is part of the record semantics so future readers can verify older chains.

## Hash chain

Conceptually:

`record_hash = SHA256(canonical_record_without_record_hash || previous_hash)`

The genesis record uses a documented zero/sentinel previous hash. Exact byte framing must be defined in implementation tests to avoid ambiguity.

## Events that must be audited

- login/logout and authentication failures once authentication exists
- role/identity changes
- policy creation, validation, activation, retirement, rollback
- system configuration changes
- source/sensor changes
- model/profile changes
- classification overrides
- alert disposition changes
- action request, approval, execution, failure, and rollback
- enforcement-mode changes
- audit verification attempts/results
- export operations
- security-relevant administrative operations

Routine high-volume packet events belong in telemetry, not the audit ledger, unless they result in a material decision/action.

## Verification

The verifier reads records in sequence and checks:

1. sequence continuity
2. canonical hash of each record
3. linkage to the previous record hash
4. supported algorithm/canonicalization version
5. optional checkpoint signatures in later releases

Verification reports the first failing sequence and does not modify records.

## Truncation detection

A local hash chain alone cannot prove that the tail was deleted by an attacker with database control. Hardened deployments should periodically publish or persist signed/checkpoint hashes to a separately protected location. This is planned for a later phase.

## Storage

Audit records use a dedicated append-only write path. Application APIs should not expose update/delete operations for audit rows.

## Privacy

Audit records should contain identifiers and hashes sufficient for accountability without unnecessarily copying sensitive payloads. If referenced evidence expires under retention policy, the audit record remains and records the reference, not the deleted content itself.

## Testing

Required tests include:

- deterministic canonicalization
- modification detection
- insertion/reordering detection
- broken previous-hash detection
- genesis behavior
- mixed supported versions
- verification of a large chain
- transaction failure behavior
- concurrent audit writes preserving sequence/link integrity
