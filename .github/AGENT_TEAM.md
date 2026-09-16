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

PrivaShield uses two separate repository-native daily workflows.

### Daily Project Health

`Daily Project Health` is deterministic quality/status automation. It runs Ruff, Pytest, Python dependency auditing, inventories open pull requests, and reports results to [Program Board #14](https://github.com/drewc611/Privashield/issues/14).

It does not deploy, release, merge, enable packet enforcement, change credentials, or modify production state.

### Daily Agent Progress

`Daily Agent Progress` is the bounded GitHub Copilot implementation loop. It runs after the deterministic health workflow and may produce at most one small candidate per run.

The AI job receives read-only repository permissions plus permission to make Copilot inference requests. It has no repository write token and no shell, GitHub, network, or subagent tools. It may edit only the isolated Actions workspace using file-level tools.

Before anything can leave that workspace, deterministic guards require all of the following:

- no more than 20 changed files
- changed paths only under approved implementation/test/documentation directories
- no `.github` or root governance/configuration changes
- no symbolic links
- no file deletions
- patch size no greater than 512 KiB
- `git diff --check`
- Ruff passing
- Pytest passing
- dashboard JavaScript parse passing
- Docker Compose validation passing

Only after those checks may a separate non-AI publisher job push a review branch and request a **draft** pull request. The workflow never merges that pull request. If GitHub blocks workflow-created PRs, the validated candidate branch remains for human review and the Program Board records the condition.

The daily progress workflow is not authorized to change privileged enforcement, AI authority, sensitive-data retention, secrets, repository governance, releases, deployment state, or any other human-approval gate in the Agent Harness.

## Escalation sequence

1. Project Manager identifies the highest-value safe slice.
2. Relevant implementation agent prepares isolated work.
3. Security Architect reviews security-sensitive changes.
4. QA and Release verifies gates and rollback behavior.
5. Product and Documentation updates public/project documentation.
6. Human approval is requested whenever the shared harness requires it.
