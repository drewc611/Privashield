# Release Process

## Versioning

Use Semantic Versioning once tagged releases begin. Before `1.0.0`, minor releases may contain breaking changes, but those changes must still be documented clearly.

## Release channels

- development: `main`, not a production guarantee
- pre-release: tagged alpha/beta/rc builds for evaluation
- stable: qualified releases meeting the documented release gates

## Release candidate requirements

A release candidate must have:

- passing required CI checks
- reviewed changelog and release notes
- versioned database migrations
- API/schema compatibility review
- security/privacy documentation updated
- dependency and secret scans passing at the defined severity threshold
- container/image scan when images are shipped
- SBOM generation
- license/dependency review for newly introduced components
- upgrade and rollback considerations documented
- checksums and signing/provenance where implemented

## Security qualification

A release represented as production-ready must additionally demonstrate:

- authentication/RBAC appropriate to its deployment scope
- no unresolved critical/high vulnerabilities affecting the shipped path without an explicit documented exception
- successful backup/restore test
- audit-chain verification test
- parser/security negative testing for changed hostile-input paths
- enforcement rollback/failure tests for any active enforcement capability
- AI regression results for changed default model/profile behavior

## Artifact integrity

Published artifacts should include:

- version/tag
- source commit SHA
- SBOM
- SHA-256 checksums
- signatures/attestations when release automation supports them
- container digests for published images

## Release notes

Release notes identify:

- user-visible changes
- security fixes without prematurely exposing uncoordinated exploit detail
- breaking changes
- migration requirements
- new privileges/network exposure
- new/changed AI models
- known issues
- rollback constraints

## Rollback

Every release with a data migration or enforcement behavior change must state whether application rollback is compatible with the migrated state. Where it is not, the recovery path uses a validated backup/restore procedure.

## Hotfixes

Security hotfixes may use an accelerated process, but do not waive testing of the affected path, artifact integrity, or documentation of the fix.
