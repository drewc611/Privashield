# Architecture Decision Records

Architecture Decision Records capture consequential decisions that are expensive to reverse or materially affect security, interfaces, deployment, data, or operations.

## Status values

- Proposed
- Accepted
- Superseded
- Deprecated
- Rejected

## Naming

Use sequential files such as `0004-short-decision-title.md`.

## Template

```markdown
# ADR-NNNN: Decision title

- Status: Proposed
- Date: YYYY-MM-DD

## Context

What problem or constraint requires a decision?

## Decision

What is being decided?

## Consequences

What benefits, costs, risks, and follow-up work result?

## Alternatives considered

What credible alternatives were considered and why were they not selected?
```

Accepted ADRs are not rewritten to make history cleaner. If a decision changes, add a new ADR that supersedes the old one.
