# Security audit — Privashield — 2026-09-27

Part of a 22-repository audit of this account. The cross-repository report (method, pain points, business impact, solution analysis, roadmap) is published at https://claude.ai/artifact/KgdrC9eNyCwdqjvSfwMNuB.

## Summary for this repository

| Severity | Count |
|---|---|
| Medium | 1 |
| Low | 3 |

**AI-generated placeholder / default credential findings (★):** PS-1 (open), PS-2 (compose fixed in this PR)

Automated passes run against this repository: gitleaks 8.24.2 (full history and tree), the placeholder-credential checker now shipped in `scripts/`, semgrep 1.178.0 (`p/security-audit`, `p/secrets`, `p/owasp-top-ten`, `p/github-actions`), bandit, pip-audit and npm audit where applicable, plus a manual review of auth, input handling, workflows and deployment files.

## Findings

| ID | Severity | Category | Location | Evidence | Impact | Fix | Status |
|---|---|---|---|---|---|---|---|
| PS-1 ★ | Medium | Anonymous requests are ADMINISTRATOR when auth is disabled (the default) | `apps/api/privashield_api/config.py:18; auth.py:86-96; docker-compose.yml:50; .env.example:9` | `auth_mode = "disabled"`; `disabled_context()` → `role=Role.ADMINISTRATOR`; the dashboard nginx proxies `/api/` | Anyone who reaches the dashboard port can create durable admin principals, register policies and drive response. No startup guard ties `environment=production` to `auth_mode=local`. Documented as a loopback-only development default. | Refuse to start with `auth_mode=disabled` unless `environment=development` and the bind is loopback; default to `local`. Left in place, annotated, pending the owner's decision. | open |
| PS-2 ★ | Low | Default database password | `config.py:14-16; docker-compose.yml:7,48` | `POSTGRES_PASSWORD:-privashield` in compose and in the code default | Guessable password inside the container network. | Compose now requires `POSTGRES_PASSWORD` (`:?`). The code default in `config.py` should follow. | compose fixed in this PR |
| PS-3 | Low | Floating images and unpinned Python ranges | `docker-compose.yml:30,151; pyproject.toml:13-24` | `ollama/ollama:latest`, `zeek/zeek:lts`, `fastapi>=0.115,<1.0` | Non-reproducible builds. | Pin image digests; add a lock file. | open |
| PS-4 | Low | No request body cap; unbounded metadata | `schemas.py:55,176; main.py` | `metadata: dict[str, Any]` unbounded; no ASGI body-limit middleware | Large payloads into Postgres/NATS. | Content-Length cap middleware; bound metadata size. | open |

## Guardrails added in this change

- `scripts/check-placeholder-secrets.sh` — fails the build on placeholder credentials, secret defaults, disabled-auth defaults, `debug=True`, literal secret assignments, private keys and committed `.env` files.
- `.gitleaks.toml` — gitleaks defaults plus custom placeholder rules and a fixture allowlist.
- `.github/workflows/secret-scan.yml` — runs both on every push and pull request and weekly over full history (SHA-pinned actions).
- `.pre-commit-config.yaml` — the same checks locally; run `pre-commit install` once.
- `docs/security/AI-CODING-GUARDRAILS.md` — the binding rules for any AI-assisted change, with references.
- A "Security rules for AI-assisted changes" section in `CLAUDE.md` (and `AGENTS.md` / Copilot instructions where present).
- `.gitignore` rules for `.env`, keys and Terraform state where they were missing.

See the cross-repository report for the fail-closed pattern by language and the prioritised fix list.
