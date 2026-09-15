# Software Supply Chain

## Objective

Reduce the chance that compromised dependencies, build systems, model artifacts, containers, or publishing credentials can subvert PrivaShield.

## Dependency policy

- Minimize dependencies, especially in privileged and parser components.
- Pin or lock dependency versions through language-standard lock files.
- Review new dependencies for maintenance health, license, transitive risk, and necessity.
- Prefer well-established libraries for cryptography, authentication, parsing, and networking primitives.
- Remove unused dependencies promptly.

## Automated scanning

The project should run:

- secret scanning
- software composition/dependency analysis
- static application security testing
- container scanning once images are built
- license checks where practical

Critical/high findings require review before release. Exceptions must be explicit, time bounded, and documented.

## SBOM

Release artifacts should include an SBOM in a standard format such as CycloneDX or SPDX. The SBOM should cover shipped application dependencies and container layers as tooling permits.

## Build integrity

Release builds should be automated from a clean CI environment with minimal token permissions. Build inputs and source commit SHAs must be identifiable.

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

## Dependency updates

Automated update tooling may open pull requests, but updates are not auto-merged solely because tests compile. Security-sensitive dependency changes require normal review and regression tests.

## Compromise response

If a dependency, image, model, or build system is compromised:

1. identify affected versions/artifacts
2. stop publication if needed
3. revoke/rotate affected credentials
4. rebuild from trusted inputs
5. publish checksums/advisory information
6. update SBOM and release notes
7. add regression/detection checks where feasible
