# Contributing to PrivaShield

PrivaShield welcomes contributions that improve detection quality, privacy, resilience, usability, performance, documentation, and operational safety.

## Before you start

Read:

- `SECURITY.md`
- `CODE_OF_CONDUCT.md`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY_ARCHITECTURE.md`
- `docs/SDLC.md`

For substantial changes, open an issue or architecture discussion before implementation. Changes that alter trust boundaries, network enforcement, privileged execution, AI authority, data retention, cryptographic logging, or public APIs should include an ADR.

## Development principles

- Prefer small, reviewable changes.
- Keep enforcement deterministic and bounded.
- Treat model output as untrusted.
- Avoid hidden network calls in local-first components.
- Default to least privilege and minimum data retention.
- Add tests with every behavior change.
- Never commit secrets, real customer telemetry, or sensitive packet captures.
- Preserve backward compatibility for stable APIs unless a documented breaking change is approved.

## Branch and pull request workflow

1. Create a focused branch from `main`.
2. Make the smallest coherent change.
3. Add or update tests and documentation.
4. Run formatting, linting, type checks, unit tests, and relevant integration tests locally.
5. Open a pull request using the repository template.
6. Address review comments and keep the branch current.
7. Use squash merge unless the maintainers choose otherwise for a specific change.

## Commit messages

Use concise conventional-style subjects when practical, for example:

- `feat: add normalized event schema`
- `fix: reject unsigned policy bundle`
- `docs: document audit hash chain`
- `test: add parser fuzz regression`

## Definition of done

A change is done when:

- acceptance criteria are met
- relevant tests pass
- new external behavior is documented
- security/privacy impact is considered
- logging and metrics are sufficient to operate the feature
- rollback/failure behavior is documented for risky changes
- dependencies are justified and pinned appropriately

## Architecture Decision Records

Create ADRs under `docs/adr/` for decisions that are difficult to reverse or materially affect security, deployment, data, APIs, or runtime architecture.

## Security-sensitive contributions

Do not submit public proof-of-concept exploit code for an undisclosed vulnerability. Follow `SECURITY.md` instead.
