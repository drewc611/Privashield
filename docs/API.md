# API Contract

## Conventions

Base path: `/api/v1`

- JSON request/response bodies unless otherwise noted
- UTC timestamps in RFC 3339 format
- UUIDv7 preferred for sortable domain identifiers when implementation support is stable; UUIDv4 is acceptable initially
- structured error envelopes
- pagination for collection endpoints
- optimistic version fields for mutable configuration/policy resources
- Server-Sent Events or WebSocket for live dashboard updates

## Error envelope

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request failed validation",
    "details": [],
    "request_id": "..."
  }
}
```

## Health and status

### GET `/health`
Liveness check for the API process.

### GET `/system/status`
Returns database, event bus, workers, model provider, sensors, audit verifier, and enforcement-mode state.

## Events

### POST `/events`
Ingest a normalized or adapter-tagged security event.

Required logical fields: `source`, `event_type`, `observed_at`, `severity`, and `payload` or structured context.

Response: accepted canonical event identifier and ingestion status.

### GET `/events`
Filters: time range, source, event type, severity, subject, network address, correlation ID, processing status.

### GET `/events/{event_id}`
Returns the canonical event plus evidence references and derived findings the caller is authorized to view.

### GET `/events/stream`
Streams newly accepted events and state changes to the local dashboard.

## Alerts

### GET `/alerts`
Filters by status, severity, detector, source, subject, time, and assigned analyst.

### GET `/alerts/{alert_id}`
Returns alert, linked events/findings, decisions, AI summaries, and lifecycle history.

### PATCH `/alerts/{alert_id}`
Permitted changes include acknowledgement, assignment, disposition, and notes. Every mutation creates an audit record.

## Classifications

### POST `/classifications`
Creates a classification job against bounded text/content or an evidence reference.

### GET `/classifications`
Returns classification findings with category, confidence, span/reference, detector/model provenance, and policy outcome.

### GET `/classifications/{classification_id}`
Returns one classification result.

## AI analysis

### POST `/analysis`
Creates an asynchronous analysis request.

Example logical request fields:

- `analysis_type`: `threat_summary`, `classification`, `remediation_assist`, `analyst_question`
- `event_ids` / `alert_id`
- bounded analyst question where applicable
- requested local model profile

The endpoint returns `202 Accepted` and an analysis job ID.

### GET `/analysis/{analysis_id}`
Returns state, model/provider metadata, prompt-template version, evidence references, structured output, confidence/uncertainty metadata, and failure reason when applicable.

## Policies

Signed policy governance is simulation-only. The API stores only an Ed25519 public verification key and cannot sign policy content. Actor strings are not identity-verified until RBAC/identity integration is implemented.

### GET `/policies/capabilities`
Returns whether public-key verification is configured, the configured key ID, the Ed25519 algorithm, mandatory human-approval state, and `privileged_execution=false`.

### POST `/policies/revisions`
Registers an already signed policy revision after Ed25519 verification. Revisions are immutable signed documents with monotonically increasing versions.

### GET `/policies/{policy_id}/revisions`
Lists stored revisions newest first.

### GET `/policies/{policy_id}/revisions/{version}`
Returns one stored revision including digest, signature metadata, lifecycle state, and non-enforcement state.

### POST `/policies/{policy_id}/revisions/{version}/approve`
Approves a draft revision. The approving actor string must differ from the actor string that registered the revision. Signature and digest are re-verified before approval.

### POST `/policies/{policy_id}/revisions/{version}/activate`
Activates an approved revision for simulation governance only. Signature and digest are re-verified. Activation does not create or execute a response action.

### GET `/policies/{policy_id}/active`
Returns the currently active simulation-governance revision, if any.

### GET `/policies/{policy_id}/history`
Returns append-only registration, approval, activation, supersession, and rollback history.

### POST `/policies/{policy_id}/rollback`
Selects a previously approved older revision, re-verifies its signature/digest, and makes it active for simulation governance. This is policy revision rollback, not privileged-enforcement rollback qualification.

See `docs/POLICY_GOVERNANCE.md` for the complete signing, key-management, lifecycle, and safety model.

## Sources

### GET `/sources`
Lists configured sensors and ingestion sources with health and capabilities.

### POST `/sources`
Registers/configures a source.

### PATCH `/sources/{source_id}`
Changes bounded source configuration.

### POST `/sources/{source_id}/test`
Runs a non-destructive connectivity/capability test.

## Models

### GET `/models`
Lists configured model providers/models and health. Must never return secrets.

### POST `/models/test`
Runs a bounded inference health test.

## Configuration

### GET `/configuration`
Returns non-secret effective configuration and version metadata.

### PATCH `/configuration`
Updates approved mutable configuration. Secret values use dedicated secret mechanisms and are not returned by read APIs.

## Decisions and actions

### GET `/decisions`
Returns policy/detection decisions. Phase 1 is observe-only.

### GET `/actions`
Returns requested or historical response actions.

### POST `/actions/{action_id}/approve`
Future enforcement workflow. Must enforce role/policy requirements.

### POST `/actions/{action_id}/rollback`
Future bounded rollback workflow where the adapter supports reversal.

## Audit

### GET `/audit`
Returns paginated audit metadata according to caller authorization.

### GET `/audit/{audit_id}`
Returns a specific record including chain linkage.

### POST `/audit/verify`
Verifies a requested chain range or the full local chain. Verification never repairs or rewrites records.

## Authentication

Phase 1 may support a local administrative bootstrap mode for loopback-only evaluation. Before non-loopback or multi-user use, authenticated sessions and role-based authorization are mandatory.

Planned roles:

- `viewer`
- `analyst`
- `operator`
- `administrator`
- `auditor`

## Idempotency

Mutating operations that can be safely retried should accept an idempotency key. Event sources should provide stable source event IDs where possible so duplicate ingestion can be detected.

## API evolution

Breaking changes require a versioned API or documented migration. Removing stable fields requires a deprecation window after the project reaches stable releases.
