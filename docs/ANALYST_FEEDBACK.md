# Analyst Feedback and Labeling

PrivaShield supports structured analyst feedback for security events and deterministic incident-correlation candidates. The feedback loop creates durable labels that can later be used for detector evaluation, quality measurement, and controlled model/rule improvement.

## Supported labels

- `true_positive`
- `false_positive`
- `benign`
- `needs_review`

Feedback may target either:

- a stored `SecurityEvent` UUID; or
- a stable incident correlation UUID returned by the cross-sensor correlation engine.

## API

### Create feedback

```http
POST /api/v1/feedback
Content-Type: application/json

{
  "target_type": "event",
  "target_id": "00000000-0000-0000-0000-000000000001",
  "label": "true_positive",
  "detector": "suricata",
  "note": "Confirmed by analyst review.",
  "tags": ["validated", "ids"]
}
```

Event targets must already exist in PrivaShield. Incident targets use the stable correlation UUID and are accepted even though separate incident-record persistence remains future work.

### List feedback

```http
GET /api/v1/feedback?label=false_positive&target_type=event
```

Optional filters:

- `target_type`
- `target_id`
- `label`
- `limit`

### Feedback statistics

```http
GET /api/v1/feedback/stats
```

Returns total feedback records plus counts by label and target type.

## Persistence

When PostgreSQL is enabled, feedback is stored in the `analyst_feedback` table. Local test/evaluation mode uses an in-memory repository with the same API contract.

Feedback creation is also written to the tamper-evident audit ledger. The audit ledger stores the feedback payload hash rather than duplicating the full analyst note.

## Identity boundary

PrivaShield does not yet have role-based authentication or external identity-provider integration. Therefore feedback records explicitly return:

```text
identity_verified=false
```

The audit actor is recorded as `analyst-unverified`. This prevents the current local administrative mode from falsely representing a submitted label as cryptographically authenticated analyst attribution.

Verified analyst identity, role checks, and multi-user audit attribution belong to the operator and enterprise hardening phase.

## Model and detector authority

Feedback is evidence, not an automatic control signal.

Creating a feedback record does **not**:

- retrain or fine-tune a model;
- change a detector threshold;
- rewrite a rule pack;
- activate a firewall policy;
- trigger quarantine or SOAR;
- merge code or configuration changes;
- change AI authority.

Future evaluation/training workflows must use versioned datasets, reproducible benchmarks, explicit promotion gates, and human-reviewed model/rule changes.

## Data handling

Analyst notes should contain only information necessary to explain the disposition. Do not paste secrets, credentials, full packet payloads, or unrelated personal data into feedback notes.
