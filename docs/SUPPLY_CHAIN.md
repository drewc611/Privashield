# Software Supply Chain

## Objective

Reduce the chance that compromised dependencies, build systems, model artifacts, containers, or publishing credentials can subvert PrivaShield.

## Dependency policy

- Minimize dependencies, especially in privileged and parser components.
- Pin or lock dependency versions through language-standard lock files where practical.
- Review new dependencies for maintenance health, license, transitive risk, and necessity.
- Prefer well-established libraries for cryptography, authentication, parsing, and networking primitives.
- Remove unused dependencies promptly.

## Automated scanning

The repository currently uses:

- CodeQL static analysis
- Python dependency auditing
- pull-request dependency review
- Dependabot dependency updates
- CI lint, unit/integration tests, detection-regression thresholds, dashboard syntax validation, and Docker Compose validation
- CycloneDX SBOM generation for the installed Python runtime environment

Planned follow-up controls include automated secret-scanning policy validation, container scanning, build provenance/attestation, and signed release artifacts.

Critical/high findings require review before release. Exceptions must be explicit, time bounded, and documented.

## SBOM

CI generates a CycloneDX 1.6 JSON SBOM after the normal application quality gates pass.

The SBOM job:

1. creates a clean Python 3.12 virtual environment;
2. installs the PrivaShield runtime package and runtime dependencies into that environment;
3. uses pinned `cyclonedx-bom` tooling outside the target runtime environment;
4. generates reproducible CycloneDX JSON from the target interpreter;
5. validates the document format, schema version, and non-empty component inventory; and
6. uploads `sbom.cdx.json` as a 90-day GitHub Actions artifact.

This prevents the CI test stack and the SBOM generator itself from being mistaken for shipped application dependencies.

### Current SBOM limitations

Current CI SBOM coverage is intentionally limited to the Python application/runtime dependency environment. It does not yet claim complete coverage of:

- container-image layers or operating-system packages;
- third-party sensor container contents;
- local AI model weights;
- release bundles or desktop wrappers;
- externally installed plugins; or
- release-tag-attached artifacts.

Release qualification should expand the inventory to those shipped surfaces and attach the final SBOM to human-approved release artifacts.

## Build integrity

Release builds should be automated from a clean CI environment with minimal token permissions. Build inputs and source commit SHAs must be identifiable.

The next planned control is build provenance / artifact attestation for release-candidate artifacts. Attestation must describe what was built, from which source revision, and by which protected workflow without granting AI agents release authority.

## Artifact integrity

Published release artifacts should provide SHA-256 checksums and, as the release pipeline matures, cryptographic signatures and provenance attestations.

## Container images

- use minimal trusted base images
- pin images by digest for release builds where practical
- run application services as non-root unless technically required
- avoid unnecessary packages/tools in runtime images
- scan final images, not only source dependencies

## AI model artifacts

Model weights are dependencies. Record:

- source
- model name/version
- license
- digest where available
- expected runtime
- evaluation profile

Do not silently download or execute an unpinned model from an untrusted source.

## CI/CD permissions

CI workflows follow least privilege. Pull-request jobs from untrusted code must not receive release secrets. Publishing credentials are limited to release workflows and protected environments where supported.

The autonomous maintainer may recommend or stage ordinary repository changes, but protected workflow and release files remain human-authorized handoff points under the agent harness.

## Dependency updates

Automated update tooling may open pull requests, but updates are not auto-merged solely because tests compile. Security-sensitive dependency changes require normal review and regression tests.

## Compromise response

If a dependency, image, model, or build system is compromised:

1. identify affected versions/artifacts;
2. stop publication if needed;
3. revoke/rotate affected credentials;
4. rebuild from trusted inputs;
5. publish checksums/advisory information;
6. update SBOM and release notes; and
7. add regression/detection checks where feasible.
