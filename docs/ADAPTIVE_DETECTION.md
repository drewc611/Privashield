# Adaptive detection

The adaptive detector scores security events and learns from analyst feedback.
It lives in `apps/api/privashield_api/learning/` and depends on nothing outside
the Python standard library. ADR-0004 records why it works the way it does; this
document describes what it is and how to operate it.

## Authority

A learned score is advisory and cannot become enforcement. ADR-0001 draws that
line and `AdaptiveAssessment.advisory_only` is fixed `True` on a frozen dataclass
so callers cannot clear it. Assessments raise an analyst's attention and order a
queue. They do not activate policy, alter firewall state, or move a response
action out of its approval gate.

## Modules

`features.py` turns a `SecurityEvent` into a feature mapping. `online.py` holds
the two learners. `guard.py` decides which feedback is allowed to train and
scores the model against ground truth. `engine.py` assembles them into
`AdaptiveDetector` and handles persistence.

## Features

Extraction is deterministic, privacy-preserving and bounded, in that order of
priority.

Severity becomes a single ordinal in [0, 1]. Source, direction and port class
become one-hot flags, with a named bucket for ports worth calling out by name
(3389 as `rdp`, 4444 as `metasploit_default`). Hour of day is encoded as a
sin/cos pair so 23:30 and 00:30 sit next to each other rather than at opposite
ends of a line. Presence of a user, process or asset is itself a feature, because
a missing field is information.

Identifiers are hashed, never stored. Event type, protocol, addresses, user and
process go through blake2b into a fixed 512-bucket space, so a feature name reads
`user#476` and the original value cannot be recovered from the weights. blake2b
rather than the built-in `hash()` because Python randomizes string hashing per
process, which would silently invalidate persisted weights on every restart.
Summary text contributes at most 24 tokens whose weights sum to 1.0, so an
attacker-controlled summary cannot flood the vector.

For the network, `hash_to_dense` projects the mapping into a fixed-width vector
using signed hashing, so collisions cancel rather than compound.

## Learners

`OnlineLogisticRegression` is the default. It updates per observation with
AdaGrad per-feature learning rates and L2 regularization, and it explains any
score it produces as a per-feature contribution. Prefer it.

`OnlineMLP` is one hidden layer with tanh activations and a sigmoid output,
backpropagated from scratch. It captures feature interactions the linear model
cannot, and it cannot explain itself: `contributions` comes back empty rather
than fabricated. Its learning rate matters more than its width; measured stable
convergence sits at 0.05-0.1, and 0.3 or above does not settle.

Both clip gradients. That bounds how far any single observation can move the
model, which is a security control as much as a numerical one.

Both are deterministic. Initialization is seeded from a private `random.Random`
instance, so constructing a model never perturbs global random state, and
iteration is sorted so float accumulation is reproducible. The detection
benchmark depends on this.

## Guard

Feedback reaches the model only if it passes every check:

- the label is decided. `needs_review` carries no training signal.
- the identity is verified. Unverified feedback is weighted zero.
- the source is under its influence cap for the rolling window. The share is
  measured *after* the pending update, so the cap cannot be walked past one
  update at a time.
- the window does not look like a label flood.
- learning is not frozen.

A refusal comes back as a `RejectionReason`, not a silent no-op, so the API can
tell an analyst why their feedback did not apply.

The window is defined by time, never by insertion order. Observations are
filtered against the cutoff rather than popped off the front, because `record`
accepts an explicit timestamp and so cannot promise the history is sorted; a
single out-of-order entry used to halt pruning and leave every expired
observation behind it in the window. That matters because the cap is
`same_source / total`, so expired observations padding `total` dilute one
source's measured share. Measured against a 60-update window with one
out-of-order entry, an attacker landed 32 poisoned updates where correct
pruning allows 19.

Two consequences of that follow. A timestamp ahead of the trusted clock is
clamped back to it, since an observation dated into the future would outlive its
own window; clamping can only make an observation expire sooner, which tightens
the cap rather than loosening it. And `window_stats` is a pure read: an
observability call must not change what the guard decides next.

## Canary and rollback

Rate limits are not the defense. They slow an attacker down; measurement in
ADR-0004 shows the fraction of poisoned feedback that fits inside a workable cap
is still enough to flip a well-trained model.

The control that bounds the damage is a periodic re-check against committed
ground truth. Every `canary_interval` applied updates, the detector scores a
corpus of known-label events. If accuracy holds, that model state is
checkpointed as verified. If accuracy falls below the accepted baseline by more
than the tolerance, learning freezes and the model is restored to the last
checkpoint.

Rollback returns the model to the last state that *passed* ground truth, not to a
pristine one. Some poison that arrived before the last passing check is retained
by design. The guarantee is narrower and more useful than perfection: whatever
survives rollback still classifies the committed corpus correctly.

Two operational consequences follow. A deployment with learning enabled and no
canary corpus has no working defense against poisoning, so `status()` reports
`canary_enabled` and `has_trusted_state` explicitly. And a freeze is not
auto-reversible; clearing it is a deliberate operator act after reviewing what
happened.

## Persistence

`save()` writes JSON atomically through a temporary file and `replace()`, so a
crash mid-write cannot leave a corrupt model. JSON rather than pickle because
pickle executes arbitrary code on load, which is unacceptable for a file a
security appliance reads at startup. It also means an operator can open the model
and read its weights.

State carries a `state_version`; `from_state` refuses a version it does not
understand rather than guessing at the layout. The trusted checkpoint is
persisted alongside the live model, so a restart does not discard the rollback
target.

## The API surface

Scoring is on by default and learning is not, and the split is deliberate.
Scoring is read-only and advisory, so it costs nothing to expose. Training is a
trust-boundary change under ADR-0004, which makes it an operator's decision
rather than a default in a security product.

- `GET /learning/status` reports the detector and, more importantly, whether its
  defenses are armed.
- `GET /learning/score/{event_id}` scores one stored event.

There is no endpoint that trains the model. Feedback is the only path in, so
every update passes the guard; a second route would be a second way to move the
weights that did not.

`POST /feedback` offers each event-targeted label to the detector, and the
outcome lands in the audit ledger either way — `learning.update.applied` or
`learning.update.refused`. Recording only the successes would hide the useful
half: an analyst whose influence was capped, or a window that looked like a label
flood, is exactly what someone auditing the model's history needs to find.

### Enabled is not the same as effective

`learning_enabled` is configuration. `learning_effective` is whether feedback can
reach the model right now, and `learning_blocked_reason` names what is in the way.
They separate for four reasons, and the first is the one that bites:

- Authentication is disabled, so no analyst is a verified principal and the guard
  weights every update at zero. An operator who set the flag would otherwise see
  learning reported as on, watch the update count stay at zero, and get no
  explanation.
- Learning is switched off in configuration.
- No canary corpus is armed. Learning is refused outright in that state rather
  than merely reported, because ADR-0004 measured that the rate limits alone do
  not stop a determined poisoner; without ground truth there is no working
  defense to run under.
- The guard is frozen, which is not auto-reversible by design.

One predicate answers this, used by both the status endpoint and the feedback
path, so what an operator reads cannot drift from what actually happens.

## Ground truth

`evaluation/adaptive-canary.json` holds the corpus, committed alongside the
detection corpus and loaded rather than generated: a corpus the code could
synthesise would be a corpus an attacker could influence.

Loading validates rather than trusts. An unknown `schema_version` is refused, a
label that is anything other than 0.0 or 1.0 is refused because ground truth
cannot be a hedge, and a one-sided corpus is refused because a model that calls
everything malicious scores perfectly against an all-malicious corpus and so
could be blinded without the canary noticing.

Arming is a separate step from construction because the baseline has to be
measured rather than assumed. A detector carrying a corpus it had never been
scored against would report `canary_enabled` true with no bar to fall below,
which is the worst available outcome: the defense looks present and does nothing.
An untrained model starts at 0.5 accuracy on a balanced corpus, since it predicts
0.5 for everything and a 0.5 threshold reads that as malicious.

The baseline then ratchets. Every passing canary raises it to the new accuracy,
for the same reason the coverage floor rises: a bar that never moves stops
measuring the thing it was set to protect. Without the ratchet a model that
learned its way to perfect accuracy could be pushed back down to just above its
startup baseline without tripping anything.

## Two bounds, and only one is a security bound

ADR-0005 has the measurements; this is the shape of them.

`max_source_updates` is the security bound: updates one source may land in the
window, 20 by default. It binds exactly, and that exactness is the point. A share
of the window scales with traffic; the number of poisoned updates that moves the
verdict does not, and ADR-0004 measured that number at 15 to 25. Measured with one
compromised account beside N honest analysts, the budget holds it to 20 at every
team size, where a 35% share cap admitted 323.

`max_source_share` is a training-distribution bound. Its job is to stop one
analyst's opinions dominating what the model learns, which is a model-quality
property rather than a security one. It is floored at an even split among active
sources, because a cap below 1/N refuses everyone once N sources share the window
evenly — which is how a team of three or fewer used to stall at about twenty
updates and never recover.

Honest throughput is the budget times the number of active analysts:

| Active analysts | 1 | 2 | 3 | 4 | 6 | 10 |
| --------------- | - | - | - | - | - | -- |
| Honest updates per window | 20 | 40 | 60 | 80 | 120 | 200 |
| Poisoned updates one account can land | 20 | 20 | 20 | 20 | 20 | 20 |

Twenty updates per analyst per 24-hour window suits triage and does not suit bulk
labelling, so the budget is configuration and `status()` reports it alongside
`active_sources`. Raising it weakens the bound in direct proportion; the
arithmetic is here so that is a decision rather than a surprise.

Neither bound is the control that limits damage. The canary and rollback are, and
a single-analyst deployment is relying on them more heavily than a larger one,
because volume alone cannot distinguish the analyst from a compromised analyst
when there is only one.

## Durability

Learned state is persisted to `adaptive_state_path`, and until recently only at a
clean shutdown. That was a defect rather than a limitation: with the path unset,
which is the default, learned state never reached disk at all, so a deployment
could train for a month, restart, and silently begin again from zero. A model
that forgets on restart is indistinguishable from one that does not work.

Checkpoints now ride the canary. The state that just passed ground truth is the
state worth keeping, so the trusted checkpoint and the durable one are the same
thing, and an ungraceful stop costs at most the updates since the last check
rather than the whole model. `status()` reports `state_durable` so the in-memory
case is visible.

The write happens through `asyncio.to_thread`, not inline. `learn` is
deliberately synchronous and free of I/O, which is what makes it atomic under
asyncio: two concurrent feedback requests cannot interleave a model update
because there is no await for the loop to switch on. Adding one, including a save,
would introduce a lost-update race. The file write is roughly 4.5 ms, and on the
event loop that would stall every other in-flight request rather than just the one
doing the writing.

## Measured cost

Numbers from this machine, so treat them as orders of magnitude rather than a
specification:

| Path | Cost |
| ---- | ---- |
| `extract_features`, one event | 17 us |
| `score`, trained model | 27 us |
| `guard.evaluate`, 500-entry window | 9 us |
| `guard.evaluate`, 5,000-entry window | 72 us |
| `save`, 814 weights | 4.5 ms, 134 KiB |
| `build_prompt`, 25 events | 1.6 ms |
| `scan_for_injection`, 25 events | 0.74 ms |

Two things worth knowing from that. Scoring is cheap enough to run per event.
`guard.evaluate` is linear in window occupancy, which sounds worse than it is: the
influence cap means a large window requires many analysts, so a ten-analyst site
labelling a hundred events each per day sits near the 1,000-entry mark and pays
about 15 us. The persisted model plateaus at roughly 814 weights and 134 KiB
because the feature space is bounded by the 512-bucket hash dimension, so state
does not grow without limit however long the detector runs.

## Operating it

`status()` returns model kind, update count, freeze state and reason, canary
baseline and cadence, whether a canary and a checkpoint exist, per-source window
counts, and the ten highest-weighted features. Watch three things: whether
learning is frozen, whether a canary is wired at all, and whether the top
features still look like security signal rather than one site's noise.

Snapshot the state file with the rest of the appliance's data. Losing it costs
the tuning, not the product; detection content in the rules and correlation
engines is unaffected.
