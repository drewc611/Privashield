# PrivaShield GitHub Agent Team

PrivaShield uses a bounded specialist-agent model for repository work. These agents live in GitHub under `.github/agents/` and operate under the authoritative rules in `.github/AGENT_HARNESS.md`.

## Team

| Agent | Primary responsibility | File |
| --- | --- | --- |
| Project Manager | Scope, sequencing, blockers, roadmap truth, daily delivery priorities | `.github/agents/project-manager.agent.md` |
| Security Architect | Threat model, privacy boundaries, secure defaults, auditability, enforcement safety | `.github/agents/security-architect.agent.md` |
| Backend Engineer | FastAPI, schemas, persistence, collectors, NATS, Ollama adapters | `.github/agents/backend-engineer.agent.md` |
| Dashboard Engineer | Local security console, live feed, analyst UI, simulation controls | `.github/agents/frontend-dashboard.agent.md` |
| QA and Release | Regression coverage, CI gates, dependency/security findings, release readiness | `.github/agents/qa-release.agent.md` |
| Product and Documentation | README, diagrams, roadmap, API/docs accuracy, release messaging | `.github/agents/product-docs.agent.md` |

## Shared harness

Every agent must read `.github/AGENT_HARNESS.md` before changing the repository. Agent-specific instructions can narrow the harness but cannot weaken it.

Human approval is required before privileged enforcement, changes to AI authority, expanded sensitive-data retention, licensing or repository-visibility changes, branch/ruleset changes, releases, production deployment, destructive data/history operations, or paid third-party infrastructure.

## Daily GitHub operations

The repository-native `Daily Project Health` workflow runs in GitHub Actions and posts results to [Program Board #14](https://github.com/drewc611/Privashield/issues/14).

It performs bounded health work only:

- Ruff lint
- Pytest regression suite
- Python dependency audit
- open pull-request inventory
- persistent daily Program Board reporting

It does not deploy, release, merge, enable packet enforcement, change credentials, or modify production state.

## Escalation sequence

1. Project Manager identifies the highest-value safe slice.
2. Relevant implementation agent prepares isolated work.
3. Security Architect reviews security-sensitive changes.
4. QA and Release verifies gates and rollback behavior.
5. Product and Documentation updates public/project documentation.
6. Human approval is requested whenever the shared harness requires it.
