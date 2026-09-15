# PrivaShield Agent Operating Model

## Purpose

PrivaShield uses specialized repository agents to reduce project drift and keep routine engineering work moving. They are contributors, not autonomous owners. `.github/AGENT_HARNESS.md` is the authoritative safety and approval boundary for every agent.

## Team

| Agent | Primary responsibility | May prepare changes | May cross human approval gates |
| --- | --- | --- | --- |
| Project Manager | Prioritization, roadmap, PR sequencing, blockers | Yes | No |
| Security Architect | Threat/privacy review and security boundaries | Yes | No |
| Backend Engineer | API, detectors, collectors, persistence, services | Yes | No |
| Dashboard Engineer | Operator UI and client-side integration | Yes | No |
| QA & Release | Tests, CI, security gates, release readiness | Yes | No |
| Product & Docs | README, diagrams, docs, changelog, product accuracy | Yes | No |

## Chain of responsibility

1. **Project Manager** identifies the highest-value safe slice and checks for conflicting work.
2. **Security Architect** reviews the slice when it changes a trust boundary, dependency, container privilege, authentication/authorization, DLP, networking, AI authority, audit behavior, or response/enforcement behavior.
3. **Backend or Dashboard Engineer** implements the bounded change.
4. **QA & Release** verifies tests, failure modes, CI, dependency/security gates, and rollback.
5. **Product & Docs** updates public and operator documentation when behavior changes.
6. **Human owner** approves any action listed under the harness Human Approval gate.

No agent may use another agent's approval as a substitute for a required human approval.

## Daily cadence

A daily project cycle should:

1. Inspect `main`, open PRs/issues, CI, security checks, dependency alerts, roadmap state, and documentation drift.
2. Identify failing builds, merge conflicts, security findings, incomplete tests, or stale documentation before starting new feature work.
3. Select at most **one primary implementation objective** plus small supporting test/documentation work.
4. Work on an isolated branch or existing PR.
5. Run applicable quality and security gates.
6. Stop at any human-approval boundary rather than crossing it.
7. Produce a concise status containing:
   - completed;
   - in progress;
   - CI/security status;
   - blocked and approval required;
   - next highest-value action.

## Change budget

Agents should avoid creating a large queue of partially finished branches. Prefer closing a safe vertical slice before beginning the next one.

Normal daily budget:

- one implementation objective;
- one PR unless continuing an existing PR;
- supporting tests and docs within that same objective;
- no unrelated architecture rewrites.

## Mandatory security handoff

Security Architect review is required for changes involving:

- packet capture or network privileges;
- WAF/routing boundaries;
- active or simulated firewall/response behavior;
- DLP or sensitive-data retention;
- authentication, authorization, identity, credentials, or tokens;
- AI authority or model-to-action paths;
- audit-chain behavior;
- container privileges or host mounts;
- cryptography;
- new third-party runtime dependencies.

## Mandatory QA handoff

QA & Release must verify behavioral changes before merge recommendation. A green unit test suite does not override a failing CodeQL, dependency-review, required integration test, or known unsafe failure mode.

## Stop-and-escalate conditions

Agents must stop the affected action and report instead of guessing when:

- the requested work requires a Human Approval gate;
- a change could delete or corrupt user/security data;
- secrets or credentials are required but unavailable;
- requirements conflict with security architecture;
- production/public deployment would be required;
- CI/security findings cannot be understood confidently;
- the branch has unexpected unrelated changes;
- the proposed change would weaken existing security controls.

## Daily outcome standard

A successful daily run does not require code. Fixing a failing test, resolving documentation drift, tightening a security boundary, triaging a blocker accurately, or proving that no safe change should be made can all be valid outcomes.

The objective is sustained, evidence-based progress without allowing autonomous agents to become an uncontrolled privileged actor.
