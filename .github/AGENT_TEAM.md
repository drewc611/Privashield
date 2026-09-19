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

Human approval is required before privileged enforcement, changes to AI authority, expanded sensitive-data retention, licensing or repository-visibility changes, branch/ruleset changes, agent-governance changes, releases, production deployment, destructive data/history operations, or paid third-party infrastructure.

## Machine-enforced governance

The written harness is backed by repository controls:

- `.github/agent-policy.json` defines machine-readable autonomous limits.
- `.github/scripts/validate_agent_governance.py` validates policy invariants, specialist-agent harness references, autonomous-workflow permissions, safe-output limits, compiled workflow presence, and CODEOWNERS coverage.
- CI runs `Validate agent governance` before the ordinary test suite.
- `.github/CODEOWNERS` assigns the repository owner to agent governance, workflows, security policy, licensing, and other protected paths.
- autonomous runs are forbidden from modifying the harness, policy file, validator, agent definitions, workflows, Copilot instructions, or CODEOWNERS.

A governance validation failure is a hard stop. Agents may not relax the validator or policy in the same change that would benefit from the relaxation.

## Autonomous mutation budget

The daily autonomous maintainer is limited to one coherent objective and one output per run: one issue or one draft pull request. The machine policy additionally caps ordinary autonomous changes at 12 files and 500 changed lines by default.

It may not merge, release, deploy, change secrets, enable privileged enforcement, create paid infrastructure, or modify its own authority.

A protected-path or permission failure triggers the stop rule: one issue may be created explaining the desired human-authorized change, then the run ends. The agent may not switch tools, credentials, branch tricks, or alternate APIs to bypass the boundary.

## Daily GitHub operations

PrivaShield uses two separate repository-native daily workflows with different responsibilities.

### Daily Project Health

`Daily Project Health` is deterministic status and quality automation. It runs Ruff, Pytest, Python dependency auditing, inventories open pull requests, and reports results to [Program Board #14](https://github.com/drewc611/Privashield/issues/14).

It does not deploy, release, merge, enable packet enforcement, change credentials, or modify production state.

### Daily Autonomous Maintainer

`Daily Autonomous Maintainer` is a GitHub Agentic Workflow defined in `.github/workflows/daily-autonomous-maintainer.md` and executed by its strictly compiled lock workflow.

Each run must first inspect the shared harness, roadmap, architecture/security/privacy guidance, Program Board, open issues and pull requests, and recent CI/security state. It then chooses at most one justified, bounded maintenance objective.

Its write capability is intentionally constrained through GitHub Agentic Workflow safe outputs:

- at most one new maintenance issue when implementation is not appropriate;
- at most one **draft** pull request for a safe repository improvement;
- protected-file changes fall back to an issue rather than bypassing governance;
- the maintainer cannot merge its own pull request;
- cache memory is used to avoid repeating the same work without new evidence.

The maintainer is explicitly prohibited from autonomously enabling privileged firewall/eBPF enforcement or quarantine, changing AI authority, weakening security controls, handling secrets, expanding sensitive-data retention, changing licensing/repository governance, publishing releases, deploying production infrastructure, rewriting history, or performing destructive operations.

The source workflow and generated `.lock.yml` must remain in sync. Changes to the autonomous maintainer itself require ordinary repository review rather than self-modification by the maintainer.

## Escalation sequence

1. Project Manager identifies the highest-value safe slice.
2. Relevant implementation agent prepares isolated work.
3. Security Architect reviews security-sensitive changes.
4. QA and Release verifies gates and rollback behavior.
5. Product and Documentation updates public/project documentation.
6. Human approval is requested whenever the shared harness requires it.
