# Sensor Collectors

## Purpose

PrivaShield collectors translate external sensor records into the canonical `SecurityEvent`
contract consumed by the control plane. Collectors are normalization boundaries. They should not
silently broaden the amount of personal or application data retained by PrivaShield.

## Phase 1 Sources

- Suricata EVE JSON
- Zeek JSON logs

Packet payload capture is not part of the Phase 1 collector contract.

## Privacy Defaults

Collectors retain connection and detection features needed for threat analysis while minimizing
application-layer identifiers by default. DNS names, HTTP hosts, and TLS SNI are omitted unless the
operator explicitly enables `--include-application-metadata`.

This option should be enabled only where the operator has a legitimate need and an appropriate data
retention policy.

## Suricata Mapping

Suricata EVE records map common source and destination addresses, ports, protocol, event type, flow
identifiers, application protocol, and selected alert metadata into `SecurityEvent`.

Suricata alert severities are normalized as follows:

| Suricata | PrivaShield |
| --- | --- |
| 1 | high |
| 2 | medium |
| 3 | low |
| other | info |

The source alert action is evidence only. An upstream `allowed` or `blocked` value does not cause
PrivaShield enforcement.

## Zeek Mapping

Zeek records map connection identifiers, endpoints, protocol, service, duration, byte counts,
packet counts, and connection state. The log type may come from `_path` or the collector
`--zeek-log-type` option.

Zeek events are informational at normalization time. Detection severity is assigned later by rules,
statistical analysis, or another approved detector.

## Running a Collector

Example Suricata EVE file:

```bash
PYTHONPATH=apps/api:services/collector \
python -m privashield_collector \
  --source suricata \
  --file /var/log/suricata/eve.json \
  --follow
```

Example Zeek connection log:

```bash
PYTHONPATH=apps/api:services/collector \
python -m privashield_collector \
  --source zeek \
  --file /opt/zeek/logs/current/conn.log \
  --zeek-log-type conn \
  --follow
```

The collector sends normalized events to the local control-plane endpoint at
`/api/v1/events/ingest`.

## Failure Behavior

Malformed JSON or an invalid required timestamp fails closed for that collector process. The
collector does not invent missing timestamps or silently convert malformed records into valid
events. Network submission errors are surfaced to the process rather than being discarded.

Queueing, backpressure, retry persistence, and NATS JetStream transport are planned for the next
collector iteration.
