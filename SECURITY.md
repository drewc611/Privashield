# Security Policy

PrivaShield is security-sensitive software. Vulnerability handling is part of the product architecture, not an afterthought.

## Supported versions

PrivaShield is currently pre-alpha. No release is production-supported yet. Once releases begin, this file will list supported branches and security-fix windows.

## Reporting a vulnerability

Do not open a public GitHub issue for suspected vulnerabilities, exploit chains, credential exposure, bypasses, unsafe defaults, or weaknesses that could materially reduce protection.

Use GitHub private vulnerability reporting when enabled for this repository. If that mechanism is unavailable, contact the repository owner privately through an established contact channel and include:

- affected component and version/commit
- prerequisites and environment
- reproduction steps
- observed and expected behavior
- likely impact
- logs or proof-of-concept details needed to validate the issue
- suggested mitigation, if known

Do not include real credentials, private packet captures, personal data, or third-party secrets.

## Disclosure expectations

Maintainers should acknowledge credible reports, reproduce the issue, assign severity, prepare a fix, test regression coverage, and coordinate disclosure before publishing technical exploit details.

## Security design rules

Contributions must preserve these project rules:

1. AI output is untrusted input until validated against deterministic schemas and policy.
2. LLMs do not receive authority to execute arbitrary shell commands or mutate enforcement state directly.
3. Inline enforcement must fail according to an explicit configured mode, never an accidental implementation detail.
4. Destructive or isolating actions require authorization, policy gates, audit records, and rollback paths.
5. Secrets must not be committed, logged, embedded in images, or sent to local/remote models unless explicitly permitted.
6. Packet payload retention is minimized by default. Metadata collection should be preferred where sufficient.
7. Audit events are append-only and hash chained.
8. All privileged operations must be attributable to an authenticated actor or bounded automation identity.
9. New network parsers and file parsers are treated as hostile-input boundaries and require fuzzing or equivalent negative testing.
10. Supply-chain integrity, dependency pinning, SBOM generation, and signed releases are release requirements.

## Severity

Use CVSS as one input, but prioritize exploitability, privilege, blast radius, persistence, data sensitivity, and whether the flaw can disable or subvert the security control itself.

## Security testing

The project intends to require SAST, dependency scanning, secret scanning, container scanning, unit tests, integration tests, parser fuzzing, policy tests, and release verification before production-ready milestones.
