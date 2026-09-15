# Privacy Architecture

## Objective

PrivaShield should protect privacy without becoming a new concentration point for unnecessary personal data. The platform therefore follows local-first processing, collection minimization, bounded retention, purpose limitation, and role-based visibility.

## Default data-handling rules

1. Processing remains local unless an administrator explicitly configures an external integration.
2. Raw packet payload retention is disabled by default.
3. Full files are not copied into the platform merely because they are scanned.
4. Model prompts and outputs are not automatically retained in full when they contain sensitive evidence.
5. Sensitive values in operational logs are redacted.
6. Evidence is referenced by hash/locator where full duplication is unnecessary.
7. Retention classes are configurable by data category and source.

## Data classes

PrivaShield recognizes at least:

- public/non-sensitive
- internal
- personal information / PII
- health information / PHI
- financial information
- credentials and authentication material
- secrets/keys/tokens
- security telemetry
- audit evidence

Classification is contextual. A value such as an IP address may have different privacy significance depending on environment and jurisdiction.

## Collection minimization

Sensors should collect metadata when metadata is sufficient for the detection objective. Examples:

- retain flow statistics instead of full packet content
- retain a content hash and matched classification span rather than a complete document
- retain request route/method/status rather than full HTTP bodies unless inspection policy requires bodies

## Retention

Every retained evidence type should have a retention class. Suggested classes:

- ephemeral: minutes/hours
- short: days
- standard: organization-defined operational period
- audit: longer-lived integrity evidence
- legal/preserved: explicitly held by authorized policy

Deletion of normal evidence does not rewrite audit history. Audit records should reference that evidence was deleted under a policy rather than preserve the deleted sensitive content.

## Local AI

Local inference is the default because security evidence may be highly sensitive. External model providers, if supported later, must be opt-in and must display exactly what data classes can leave the host.

## Analyst access

Sensitive evidence should be masked based on role and operational need. An alert can often communicate the category, match count, or partial redaction without exposing the original value.

## Exports

Exports can create a new privacy boundary. Export operations should:

- require authorization
- support redaction
- record an audit event
- state the included time range/data classes
- avoid including secrets by default

## Telemetry about PrivaShield

The project should not silently send usage analytics or crash data to maintainers. Any future diagnostic telemetry must be documented and opt-in.

## Privacy reviews

Features that add new telemetry sources, raw-content retention, external integrations, cross-host processing, or identity correlation require a privacy review and documentation update.
