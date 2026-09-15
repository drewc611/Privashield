# Canonical Data Model

This document defines the logical domain models for Phase 1. Persistence details may evolve, but API and event contracts should preserve these semantics.

## Common fields

Most persisted entities include:

- `id`: UUID
- `created_at`: UTC timestamp
- `updated_at`: UTC timestamp where mutable
- `tenant_id`: reserved for future multi-tenant deployments; null/single local tenant in Phase 1
- `schema_version`: integer or semantic schema identifier
- `correlation_id`: optional identifier linking related processing

## SecurityEvent

Represents normalized source telemetry.

Required fields:

- `id`
- `source_id`
- `source_event_id` when provided by source
- `event_type`
- `observed_at`
- `ingested_at`
- `severity`: `info|low|medium|high|critical`
- `direction`: optional `inbound|outbound|lateral|local|unknown`
- `subject`: actor/user/process/device identity reference where known
- `network`: optional `NetworkContext`
- `resource`: optional file/URL/service/data-object context
- `attributes`: bounded normalized key/value data
- `evidence_refs`: references to retained evidence, never an excuse to persist unlimited payloads
- `source_hash`: optional integrity/deduplication hash
- `processing_state`

## NetworkContext

- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `transport`
- `interface`
- `bytes_in`
- `bytes_out`
- `packets_in`
- `packets_out`
- `duration_ms`
- `tls_metadata`: optional bounded metadata
- `http_metadata`: optional bounded metadata
- `dns_metadata`: optional bounded metadata

Raw payload storage is off by default.

## Finding

A detector output attached to one or more events.

- `id`
- `detector_id`
- `detector_version`
- `finding_type`
- `title`
- `severity`
- `score`: normalized 0.0-1.0 where meaningful
- `confidence`: normalized 0.0-1.0 where meaningful
- `reason_codes[]`
- `event_ids[]`
- `evidence_refs[]`
- `metadata`

## Alert

An analyst-facing security case created from one or more findings/events.

- `id`
- `title`
- `severity`
- `status`: `new|acknowledged|investigating|contained|resolved|false_positive`
- `finding_ids[]`
- `event_ids[]`
- `assigned_to`
- `disposition`
- `first_observed_at`
- `last_observed_at`
- `summary`
- `tags[]`

## ClassificationResult

Represents sensitive-data classification.

- `id`
- `target_ref`
- `categories[]`: each with category, confidence, detector/model provenance, location/span/reference, and reason code
- `overall_sensitivity`
- `detector_versions[]`
- `model_run_id`: optional
- `policy_outcome`
- `review_state`: `unreviewed|confirmed|rejected|modified`

Initial standard categories:

- `pii`
- `phi`
- `financial`
- `credential`
- `secret`
- `government_identifier`
- `custom`

## AnalysisJob

Tracks asynchronous local-AI work.

- `id`
- `analysis_type`
- `state`: `queued|running|succeeded|failed|cancelled`
- `event_ids[]`
- `alert_id`
- `question`: optional bounded analyst input
- `model_profile_id`
- `prompt_template_version`
- `started_at`
- `completed_at`
- `error_code`

## ModelRun

Immutable provenance for one inference operation.

- `id`
- `provider`
- `model_name`
- `model_digest/version`
- `prompt_template_version`
- `input_evidence_refs[]`
- `parameters`: approved non-secret generation parameters
- `started_at`
- `completed_at`
- `latency_ms`
- `output_schema_version`
- `output_hash`
- `validation_state`

Sensitive full prompts/outputs should not automatically be retained. Retention is policy-controlled.

## ThreatAnalysis

Structured AI-assisted analysis result.

- `id`
- `model_run_id`
- `summary`
- `threat_type`
- `severity_assessment`
- `confidence`
- `observations[]`
- `recommended_actions[]`
- `uncertainties[]`
- `evidence_refs[]`

Recommendations are advisory unless separately converted to authorized actions.

## PolicyBundle

- `id`
- `name`
- `revision`
- `state`: `draft|validated|active|retired`
- `mode`: `observe|alert|enforce`
- `rules[]`
- `created_by`
- `validated_at`
- `activated_at`
- `content_hash`
- `signature`: future optional/required field for production policy signing

Activated revisions are immutable.

## Decision

A deterministic policy outcome.

- `id`
- `policy_id`
- `policy_revision`
- `subject_ref`
- `event_ids[]`
- `finding_ids[]`
- `action`: `allow|observe|alert|drop|rate_limit|redact|quarantine`
- `reason_codes[]`
- `confidence`: optional
- `expires_at`: optional
- `decision_context_hash`

Phase 1 restricts effective actions to `allow|observe|alert`.

## ResponseAction

Represents a requested privileged or operational action.

- `id`
- `decision_id`
- `action_type`
- `target`
- `requested_by`
- `approved_by`
- `state`: `requested|approved|executing|succeeded|failed|rejected|rolled_back`
- `adapter`
- `rollback_supported`
- `rollback_ref`
- `result_summary`
- `started_at`
- `completed_at`

## Source

- `id`
- `name`
- `source_type`
- `enabled`
- `mode`
- `health`
- `capabilities[]`
- `configuration_ref`
- `last_event_at`

Secrets are referenced, not returned in source records.

## SystemConfiguration

Versioned non-secret configuration metadata.

- `id`
- `revision`
- `settings`
- `created_by`
- `activated_at`
- `content_hash`

Secret material belongs in a dedicated secret store or Docker secret/file mechanism, not this model.

## AuditRecord

Immutable tamper-evident record.

- `sequence`
- `id`
- `occurred_at`
- `actor_type`: `user|service|automation|system`
- `actor_id`
- `action`
- `resource_type`
- `resource_id`
- `outcome`
- `reason_code`
- `request_id`
- `metadata_hash`
- `previous_hash`
- `record_hash`
- `hash_algorithm`

## EvidenceReference

- `id`
- `kind`
- `locator`
- `content_hash`
- `content_type`
- `size_bytes`
- `retention_class`
- `sensitivity`

Evidence references permit the system to correlate analysis without copying arbitrary raw content into every record.

## Relationships

```text
Source -> SecurityEvent -> Finding -> Alert
                   \          \
                    \          -> Decision -> ResponseAction
                     -> ClassificationResult
                     -> AnalysisJob -> ModelRun -> ThreatAnalysis

PolicyBundle -> Decision
All material mutations/actions -> AuditRecord
```

## Migration rules

- Database migrations are forward-versioned through Alembic.
- Destructive schema changes require backup/restore testing.
- Stable external fields are deprecated before removal.
- Persisted enum changes must define compatibility behavior.
- Audit records are never rewritten by ordinary schema migrations. New interpretations should be represented through version-aware readers.
