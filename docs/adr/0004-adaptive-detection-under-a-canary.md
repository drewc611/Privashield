# ADR-0004: Let the detector learn from analyst feedback, bounded by a canary with rollback

- Status: Accepted
- Date: 2026-09-23

## Context

Detection content goes stale. The signature and correlation engines encode what
was known when they were written, and every deployment sees a slightly different
mix of normal traffic, so the same rule produces different false-positive rates
on different sites. Analysts already label events through the feedback API
(`docs/ANALYST_FEEDBACK.md`), and today that labelling changes nothing about
future scoring.

Learning from that feedback moves a trust boundary. A detector that updates from
operator input is a detector an attacker can teach. The classic attack is label
poisoning: submit enough feedback marking a real attack pattern benign, and the
model stops scoring it. The failure is quiet. Every other health signal, uptime,
throughput, error rate, ingestion lag, still looks fine, and the first symptom is
a missed intrusion.

ADR-0001 already forbids a model from reaching enforcement. That bounds the blast
radius but does not address a detector being blinded, because blinding is a
failure to raise an alert, not an unauthorized action.

## Decision

Analyst feedback trains an online classifier, under four controls, in this order:

1. Only decided labels train. `true_positive`, `false_positive` and `benign`
   carry a target; `needs_review` does not. Indecision is not a label.
2. Only verified identities train. Unverified feedback is weighted zero, which
   refuses it outright rather than admitting it at reduced strength.
3. Per-source influence is capped over a rolling window, and a flood of
   identical labels is refused.
4. The model is re-checked against committed ground truth every N applied
   updates. On degradation, learning freezes and the model is rolled back to its
   last state that passed that check.

Features are hashed into a fixed dimension with blake2b, so raw addresses,
usernames and process paths never become weights. State persists as JSON, not
pickle, because a security appliance must not execute arbitrary code when it
loads its own model at startup.

Every score carries `advisory_only=True` as a structural property of the
dataclass rather than a configuration flag, and that is asserted in tests.

## Consequences

Benefits:

- per-site tuning without shipping new rules
- feedback becomes a control loop rather than a record
- weights are inspectable, and the linear model explains any score it gives
- a poisoned model returns to a verified state instead of staying broken

Costs:

- a new persisted artifact to back up, version and reason about
- the canary corpus is now load-bearing; a weak corpus is a weak control
- rollback discards honest learning that arrived alongside the poison
- an operator can freeze learning and not notice, so freeze state has to surface

## Alternatives considered

### Rate limits alone

Rejected on measurement, not principle. Against a model trained on 60 updates,
the fraction of poisoned feedback that fits inside an influence cap is still
enough to flip its verdict:

| Influence cap | Poisoned updates applied | Score on the known attack |
| ------------- | ------------------------ | ------------------------- |
| 5%            | 0                        | 0.956 (unchanged)         |
| 10%           | 1                        | 0.887                     |
| 20%           | 15                       | 0.265                     |
| 30%           | 25                       | 0.136                     |

Only a 5-10% cap holds, and a cap that tight starves a real analyst team of
influence over its own detector. Caps raise an attacker's cost; they do not bound
the damage. `test_rate_limits_alone_do_not_stop_a_determined_poisoner` keeps this
result in the suite so the conclusion is not quietly forgotten.

### Freeze on canary failure, without rollback

Rejected. Freezing stops further damage and leaves the poisoned weights serving
traffic, producing a detector that is both blind and unteachable. Measured at a
ten-update canary cadence, the poison landing between two checks took a 0.99
score to 0.32 before the freeze triggered. Detection has to come with reversal.

### Periodic offline retraining instead of online learning

Rejected for Phase 1. It needs a training corpus, a schedule, and somewhere to
run it, none of which exist in a local-first single-appliance deployment
(ADR-0002, ADR-0003). It also does not remove the poisoning problem; it moves it
into a batch job where the labels are still analyst-supplied.

### A deep network instead of a linear model

Rejected as the default, and kept as an option. `OnlineMLP` is implemented and
tested for cases where feature interactions matter, but the default is logistic
regression because it explains its scores per feature. A detector whose output an
analyst cannot interrogate is a detector they will learn to ignore.
