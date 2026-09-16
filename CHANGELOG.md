# Changelog

All notable project changes will be documented in this file.

The project follows semantic versioning once versioned releases begin. Until then, changes are grouped under `Unreleased`.

## Unreleased

### Added

- Initial project documentation and governance foundation.
- Phase 1 architecture, requirements, API, data-model, security, SDLC, testing, deployment, and operations documentation.
- Local authentication, server-side RBAC, verified multi-user audit attribution, and authenticated dashboard/WebSocket/collector flows.
- Ed25519 signed policy governance with approval history and verified simulation-policy rollback.
- Versioned detection evaluation corpus and regression thresholds.
- Reproducible CycloneDX 1.6 SBOM generation in CI for the installed Python runtime application environment.

### Changed

- Expanded the initial README into the project entry point.
- Program Board priorities now track the current software-supply-chain and enterprise-hardening work instead of completed Phase 1 bootstrap tasks.

### Security

- Established responsible-disclosure and security-design requirements.
- Added CodeQL, dependency auditing, Dependabot, RBAC regression coverage, and CI SBOM artifact generation.
