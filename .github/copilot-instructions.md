# PrivaShield Copilot Instructions

PrivaShield is a local-first security product. Treat security, privacy, reversibility, testability, and explicit trust boundaries as product requirements.

## Non-negotiable invariants

1. AI is advisory. Model output must never directly execute privileged host, network, identity, or destructive actions.
2. Enforcement changes must pass through deterministic policy and remain disabled unless an approved phase explicitly enables them.
3. Current firewall/response behavior is observe/simulate only. Do not add packet dropping, nftables mutation, eBPF enforcement, quarantine, process termination, credential revocation, or destructive SOAR execution without a dedicated approved change.
4. Do not retain packet payloads by default. Application metadata such as DNS names, HTTP hosts, and TLS SNI must remain opt-in where existing privacy controls require it.
5. Never log secrets, credentials, authorization headers, private keys, raw tokens, or unnecessary sensitive payloads.
6. Every security-sensitive change needs tests for success, failure, rollback, and unsafe input.
7. Preserve the canonical `SecurityEvent` contract unless a versioned migration is included.
8. Keep external network dependencies optional for core local operation.

## Engineering standards

- Python 3.12+.
- FastAPI and Pydantic for control-plane APIs and contracts.
- Ruff must pass.
- Pytest must pass.
- Add type-safe schemas before wiring new external inputs into business logic.
- Prefer small services with explicit interfaces over hidden global coupling.
- Use UTC timestamps in persisted event data.
- Document architectural decisions that change trust boundaries.
- Update README, ROADMAP, API/data-model docs, and changelog when behavior materially changes.

## Pull request expectations

Before considering work complete:

- run lint and tests;
- add or update tests for the change;
- describe security/privacy implications;
- state whether enforcement behavior changed;
- identify rollback behavior;
- avoid mixing unrelated refactors into security-sensitive PRs.

All repository agents must also obey `.github/AGENT_HARNESS.md`.