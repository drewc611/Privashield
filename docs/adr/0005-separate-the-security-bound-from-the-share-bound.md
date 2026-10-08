# ADR-0005: Separate the learning security bound from the share bound

- Status: Accepted
- Date: 2026-10-08
- Refines: ADR-0004

## Context

ADR-0004 established that rate limiting is not what bounds poisoning damage — the
canary is — and set a per-source influence cap at 35% of a rolling window. That
cap turned out to do neither job well, and measurement rather than reasoning is
what showed it.

On usability, the cap is a function of team size. With N active analysts each
source holds roughly 1/N of the window, so a cap below 1/N refuses everyone once
the window fills. Measured over 600 submissions:

| Active analysts | Honest updates landed | Outcome |
| --------------- | --------------------- | ------- |
| 1 | 20 | stalls permanently |
| 2 | 20 | stalls permanently |
| 3 | 21 | stalls permanently |
| 4 | 600 | unbounded |
| 10 | 600 | unbounded |

A local-first appliance usually has one or two analysts, so the default stopped
the detector after about twenty updates. Above three analysts it stopped bounding
anything at all. A control with a cliff between "stalled" and "unbounded" is not
calibrated; it is accidental.

On resistance it is worse, and this is the finding that decided the ADR. A share
is a proportion of traffic. The number of poisoned updates that moves the verdict
is not — ADR-0004 measured it at 15 to 25. Holding one source to 35% of a
500-entry window permits about 175 observations. Measured with one compromised
account beside N honest analysts:

| Active analysts | Poisoned updates landed under a 35% cap |
| --------------- | --------------------------------------- |
| 1 | 10 |
| 2 | 10 |
| 3 | 323 |
| 10 | 323 |

323 is twenty-one times the lower bound of the danger range. No value of a share
cap fixes this, because the quantity it bounds scales with traffic while the
quantity that matters does not.

The first attempt at this measurement was wrong and worth recording. It modelled
the window as a counter with hand-rolled eviction that dropped observations from
the largest source rather than the oldest, which drains an attacker's count and
invented resistance that was not there. The numbers above come from driving the
production guard.

## Decision

Split the two bounds and name them for what they do.

`max_source_updates` is the security bound: the number of updates one source may
land in the window, whatever the team size or traffic volume. Default 20, set
from ADR-0004's measured danger range rather than chosen for feel. It binds
exactly — a compromised account lands 20 and no more, with 1, 3 or 10 honest
analysts alongside it — while honest throughput scales with the team, because N
analysts get N times the budget.

`max_source_share` stays, re-scoped to a training-distribution bound: it stops one
analyst's opinions dominating what the model learns. That is a model-quality
property, not a security one, and it is documented as such. It is now floored at
an even split among active sources (`even_split_slack / active_sources`), so it
can no longer be the thing that stalls a small team.

The canary and rollback remain the control that bounds damage. Nothing here
changes that, and the budget is not offered as a replacement for it.

## Consequences

Measured after the change:

| Active analysts | 1 | 2 | 3 | 4 | 6 | 10 |
| --------------- | - | - | - | - | - | -- |
| Honest updates landed | 20 | 40 | 60 | 80 | 120 | 200 |
| Poisoned updates landed | 20 | 20 | 20 | 20 | 20 | 20 |

Resistance improves from 323 to 20 in the worst case, and becomes flat: the bound
no longer depends on the shape of the deployment, which is the property worth
having in a security control.

Costs, stated plainly:

- Honest throughput is now bounded where it was unbounded above three analysts.
  20 updates per analyst per 24-hour window suits triage and does not suit bulk
  labelling, so `adaptive_max_source_updates` is configuration and `status()`
  reports it.
- A busy team that raises the budget weakens the bound in direct proportion. The
  arithmetic is published so that is a decision rather than a surprise.
- A single-analyst deployment still cannot distinguish the analyst from a
  compromised analyst by volume alone. Nothing in this ADR changes that, and the
  canary is what covers it.

## Alternatives considered

### A peer-relative dominance rule

This was the queued plan: refuse a source holding some multiple more than its
median peer, so the control scales with the deployment instead of with a constant.
Measured, it is better on usability (no stalling at any team size) and worse on
resistance, admitting 268 to 600 poisoned updates against the fixed cap's 323,
because with one or two sources there are no meaningful peers and the rule becomes
vacuous exactly where the deployment is most exposed.

Rejected, and the task that proposed it closed with the measurement attached. It
was the wrong fix for a correctly identified problem.

### Lowering the fixed share cap

Rejected. To hold one source under 15 observations on a 500-entry window the cap
would have to be about 3%, which refuses every honest analyst on any team smaller
than thirty. The cliff moves; it does not go away.

### Treating `label_flood_threshold` as the security bound

It already is an absolute per-source bound, and measurement confirms this shape
works, so this is close to the decision taken. Rejected only in its existing form:
it counts identical labels, so a source alternating label values multiplies its
own budget. The new bound counts updates from the source regardless of label.
The flood threshold is kept as a per-label signal.
