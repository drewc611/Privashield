# Governance

PrivaShield is maintained as an open-source security project with security-sensitive review requirements.

## Roles

### Maintainers
Maintainers approve releases, merge pull requests, manage security disclosures, set roadmap priorities, and make final decisions on architecture and project policy.

### Reviewers
Reviewers provide technical or domain review in areas such as networking, backend services, AI/ML, UI, cryptography, DevSecOps, privacy, and documentation.

### Contributors
Contributors may propose issues, documentation, code, tests, models, rules, integrations, and design changes through the documented contribution process.

## Decision making

Routine implementation choices are decided through pull-request review. Material or difficult-to-reverse decisions require an Architecture Decision Record under `docs/adr/`.

Examples include:

- changing public APIs or event schemas
- adding privileged runtime capabilities
- changing fail-open/fail-closed behavior
- selecting a new enforcement mechanism
- changing audit-chain algorithms
- adding remote AI dependencies
- introducing mandatory infrastructure components

Security concerns may override feature velocity. Maintainers may block or revert changes that weaken safety, privacy, auditability, rollback, or least privilege.

## Releases

Production-capable releases require the release criteria in `docs/RELEASE.md`. No component should be represented as production-ready solely because it is merged to `main`.

## Conflict of interest

Contributors should disclose material conflicts that could bias security evaluations, vendor selections, benchmark claims, or vulnerability handling.
