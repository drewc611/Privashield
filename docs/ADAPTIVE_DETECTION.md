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

## Operating it

`status()` returns model kind, update count, freeze state and reason, canary
baseline and cadence, whether a canary and a checkpoint exist, per-source window
counts, and the ten highest-weighted features. Watch three things: whether
learning is frozen, whether a canary is wired at all, and whether the top
features still look like security signal rather than one site's noise.

Snapshot the state file with the rest of the appliance's data. Losing it costs
the tuning, not the product; detection content in the rules and correlation
engines is unaffected.
