# Cross-Sensor Incident Correlation

PrivaShield correlates related security telemetry into deterministic incident candidates without using model output as security evidence or triggering privileged response actions.

## Purpose

Individual sensors often see only one part of an incident. A Suricata alert, a host event, an identity anomaly, and a WAF signal may describe the same activity from different control points.

The correlation engine groups events when there is concrete shared evidence and temporal proximity. It is designed to reduce analyst fragmentation while preserving direct links to the source events.

## Correlation evidence

Two events may be linked when they occur within the configured maximum time gap and share at least one of these observable indicators:

- existing `correlation_id`
- `asset_id`
- `user_id`
- a common source or destination IP address

A connected event cluster becomes a cross-sensor incident candidate only when:

- it contains at least two events; and
- it contains at least two distinct `EventSource` values.

Events from only one source are intentionally excluded from cross-sensor incident output even when they share an indicator.

## Deterministic behavior

Correlation is rules-based and reproducible.

- No LLM output participates in event linking.
- The incident correlation ID is derived deterministically from the sorted source event IDs.
- Severity is the highest source-event severity in the cluster.
- The score is a bounded evidence-strength heuristic based on shared identifiers, source diversity, and high-severity telemetry.
- Every candidate returns its event IDs, source types, shared indicators, and reasons.

The score is not a probability and must not be presented as one.

## API

### Discover recent candidates

```http
GET /api/v1/incidents/candidates?lookback_minutes=15&max_time_gap_seconds=900&limit=500
```

The endpoint evaluates recent events already stored by PrivaShield and returns bounded incident candidates.

### Correlate selected events

```http
POST /api/v1/incidents/correlate
Content-Type: application/json

{
  "event_ids": [
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002"
  ],
  "max_time_gap_seconds": 900
}
```

The selected-event endpoint is useful for analyst-driven investigation and deterministic regression testing.

## Current lifecycle boundary

This implementation produces incident candidates only.

It does **not**:

- mutate or overwrite source events;
- automatically persist a separate incident record;
- change firewall policy;
- block an IP address;
- isolate an interface or session;
- revoke credentials;
- quarantine files;
- invoke privileged SOAR actions;
- allow an AI model to create or enforce a correlation decision.

Future incident persistence and analyst disposition workflows should preserve the same evidence lineage and audit requirements.

## False-positive controls

The MVP correlation engine intentionally favors precision over broad behavioral inference:

- source diversity is mandatory;
- temporal proximity is mandatory;
- at least one concrete shared indicator is mandatory;
- process name, free-text summary similarity, and LLM semantic similarity are not sufficient evidence.

Additional indicators should be introduced only with tests and documented false-positive analysis.
