# ADR-0002: Use a modular single-machine architecture for Phase 1

- Status: Accepted
- Date: 2026-09-15

## Context

The project needs clear security boundaries and replaceable interfaces, but the first milestone must also be installable and operable by one person on one machine. A large microservice topology would add deployment, networking, authentication, tracing, and failure modes before product contracts are proven.

## Decision

Phase 1 uses a modular architecture packaged through Docker Compose with a small number of runtime processes: API, worker, dashboard, PostgreSQL, Redis, optional local model runtime, and sensor processes.

Domain models and provider interfaces remain framework-independent so components can split later without changing public contracts unnecessarily.

## Consequences

Benefits:

- faster MVP delivery
- simpler local installation and debugging
- fewer distributed-system failure modes
- preserves logical module boundaries for future extraction

Costs:

- some components share deployment lifecycle initially
- horizontal scaling is limited compared with a fully distributed architecture
- later service extraction may require additional operational work

## Alternatives considered

### Microservices from day one
Rejected because operational complexity would exceed the needs of the MVP and make security review harder.

### Single-process application including privileged enforcement
Rejected because the privileged enforcement boundary warrants process/container separation even in a single-machine deployment.
