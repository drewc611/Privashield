# PrivaShield Agent Harness

This file is authoritative for every automated or AI-assisted agent operating on PrivaShield. Agent-specific instructions may narrow these rules but may not weaken them.

## Default operating mode

Agents operate in **bounded contributor mode**. They may inspect the repository, propose work, edit files on a feature branch, add tests, update documentation, and prepare pull requests. They do not own production, security policy, credentials, or irreversible repository administration.

## Hard boundaries

Agents must never autonomously:

- enable active packet dropping, host firewall mutation, eBPF/XDP enforcement, quarantine, process termination, credential revocation, destructive SOAR, or other privileged enforcement;
- weaken authentication, authorization, encryption, audit integrity, privacy minimization, branch protections, security scanning, or required tests;
- expose, request, print, store, or commit secrets, credentials, tokens, private keys, customer data, or unnecessary sensitive payloads;
- merge a security-sensitive change when CI, dependency review, CodeQL, or required tests are failing;
- force-push protected/shared branches, rewrite published history, delete branches with unmerged work, delete releases, delete audit history, or remove security controls;
- publish packages, releases, images, production deployments, or externally accessible infrastructure without an explicit human-approved release step;
- mark roadmap items complete unless the implementation and tests exist in the repository;
- invent benchmarks, certifications, compliance status, customer claims, adoption metrics, test coverage, or production-readiness claims.

## Required gates

### Gate 1: Scope
Before editing, identify the issue, roadmap item, defect, or explicit user request being addressed. Avoid unrelated changes.

### Gate 2: Branch isolation
Code changes must be prepared on a feature/fix/docs branch or pull request. Do not bypass review by writing directly to `main` unless a human explicitly requests that exact action.

### Gate 3: Tests
Behavioral changes require tests. Security-sensitive behavior also requires negative/unsafe-input tests and failure-mode coverage.

### Gate 4: Security review
Changes involving networking, authentication, authorization, secrets, DLP, AI authority, audit logging, dependencies, containers, or future enforcement require Security Architect review or equivalent explicit security-review notes.

### Gate 5: CI
Ruff, Pytest, and applicable repository security checks must pass before an agent recommends merge.

### Gate 6: Human approval
Human approval is required before any change that:

- enables or expands privileged enforcement;
- changes the AI authority boundary;
- changes retention of packet payloads or sensitive application metadata;
- alters licensing;
- changes repository visibility;
- modifies branch/ruleset protections;
- publishes a release or production artifact;
- deploys to production or makes a service publicly reachable;
- deletes data or repository history;
- incurs paid infrastructure or third-party service cost.

## Daily-run limits

A daily agent run may:

- inspect open PRs, issues, CI, dependency/security findings, roadmap state, and documentation drift;
- fix low-risk defects on an isolated branch;
- add missing tests or documentation;
- prepare or update pull requests;
- triage and report blockers;
- propose the next safe vertical slice.

A daily run must not autonomously cross any Human Approval gate above. If blocked by one, stop that action and report the exact approval needed.

## Change budget

Prefer one coherent objective per PR. Avoid broad rewrites. If a run discovers multiple unrelated tasks, prioritize them and work only the highest-value safe slice unless explicitly directed otherwise.

## Failure behavior

If requirements conflict, CI is ambiguous, a security boundary is unclear, or a requested action could be irreversible, stop the affected action rather than guessing. Preserve existing working behavior and report the blocker.

## Audit trail

Every agent-created PR should state:

- objective;
- files/components affected;
- tests run;
- security/privacy impact;
- enforcement impact;
- rollback approach;
- unresolved risks or approvals required.

## Authority order

1. Explicit human instruction for the current task
2. This shared harness
3. Repository-wide Copilot instructions
4. Agent-specific instructions
5. General project documentation

No lower-level instruction can weaken a higher-level safety boundary.
