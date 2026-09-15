# Operations Runbook

## Operating principles

PrivaShield should remain observable, recoverable, and predictable during partial failure. Operators must be able to distinguish telemetry loss, AI degradation, database failure, and enforcement state.

## Daily health checks

Monitor:

- API readiness
- PostgreSQL availability and storage
- Redis availability and consumer lag
- worker queue depth
- sensor health and last-event timestamps
- model-provider health
- audit-chain verification status
- disk/memory/CPU pressure
- active operating/enforcement mode

## Backup

Back up PostgreSQL and any policy/configuration artifacts needed to restore service. Evidence storage is backed up according to its retention class. Backups containing sensitive security data must be protected appropriately.

## Restore

Restore testing is required, not merely backup creation. A restore procedure should verify:

1. database integrity
2. schema version
3. active policy/configuration state
4. audit-chain readability/verification
5. service readiness
6. sensor reconnection

## Incident response

If PrivaShield itself is suspected compromised:

1. preserve relevant evidence
2. restrict control-plane exposure
3. disable or freeze automated enforcement according to the safest known deployment mode
4. rotate affected credentials/signing material
5. validate binaries/images/configuration against trusted references
6. verify audit-chain integrity and identify the first anomaly
7. rebuild from trusted artifacts when integrity cannot be established

## AI degradation

If the local model provider is unavailable:

- mark AI features degraded
- continue deterministic ingestion/detection/policy
- queue only within configured limits
- avoid unlimited retries
- surface the condition in the dashboard

## Event-bus degradation

Monitor queue lag and rejected/pending events. Backpressure must be bounded. Do not silently discard security events without a metric/log/alert describing loss.

## Database degradation

The application must expose unhealthy/read-only/degraded state explicitly. Security-relevant writes that cannot be persisted must not be reported as durably completed.

## Disk pressure

Disk pressure can affect databases, logs, evidence, models, and containers. Retention/rotation should protect core state. Never delete audit records automatically to make space.

## Policy recovery

Maintain a known-good policy revision. Policy rollback should select an immutable prior revision and create a new audit event documenting the rollback.

## Audit verification

Run periodic verification. A failure is treated as an integrity incident until explained. Verification tools report problems but do not rewrite the chain.

## Upgrades

Follow `DEPLOYMENT.md` and `RELEASE.md`. Back up before migrations and validate health after upgrade.

## Operational records

Material incidents and significant false-positive/false-negative events should result in tests, issue records, or documentation changes so the failure mode does not remain tribal knowledge.
