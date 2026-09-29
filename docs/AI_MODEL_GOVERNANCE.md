# AI Model Governance

## Purpose

AI in PrivaShield supports classification, explanation, correlation, and remediation assistance. It does not replace deterministic authorization or enforcement policy.

## Authority boundary

A model may:

- classify bounded content
- summarize events and alerts
- identify possible relationships or hypotheses
- propose remediation steps
- answer analyst questions using approved evidence

A model may not directly:

- execute shell commands
- alter firewall state
- revoke credentials
- terminate sessions
- delete files
- activate policy
- modify audit history

Any future AI-proposed action must pass through deterministic schemas, policy, authorization, and an enforcement adapter.

## Provider model

All inference occurs through a provider interface. Phase 1 targets an Ollama-compatible local provider. Future providers must expose:

- provider/model identity
- version or digest where available
- health state
- timeout and resource controls
- supported context limits
- structured-output capability

Implemented as the `ThreatAnalysisProvider` protocol in
`apps/api/privashield_api/ai/provider.py`. A provider is transport: it moves a
prompt to a model and text back, and it does not parse or judge its own output.
That split is deliberate, because a backend that interpreted its own answer would
sit on the untrusted side of the boundary while behaving as though it did not.

`OllamaProvider` is the Phase 1 backend, local per ADR-0003, with temperature
fixed at 0 so a finding does not change between identical requests.
`ScriptedProvider` is a deterministic double; it ships in the package rather than
the test tree because the adversarial corpus harness needs it too, and because
without it neither prompt construction nor output validation could be exercised
without a running model.

Provider identity, model name, health (`enabled`) and timeout are exposed today.
Version or digest reporting and declared context limits are not yet implemented.

## Prompt management

Prompts are versioned artifacts. Prompts must:

- distinguish system instructions from untrusted evidence
- identify telemetry as data, never instructions
- request schema-constrained output where possible
- avoid embedding unnecessary sensitive content
- define uncertainty behavior

Implemented in `apps/api/privashield_api/ai/prompt.py`. Instructions always
precede the data, telemetry is never interpolated into instruction text, and the
untrusted block is fenced with a per-request random nonce. The nonce is the point:
a fixed delimiter can be closed early by content that guesses it. The analyst
question is fenced separately, because it arrives over the API and is untrusted
too, and because otherwise telemetry could pose as it.

Prompts are not versioned artifacts yet, and are not persisted — they embed
telemetry, and `docs/PRIVACY.md` keeps minimisation a property of the code.

Prompt changes that materially affect security outcomes require tests and version updates.

## Prompt-injection defense

Telemetry may contain attacker-generated instructions. Defenses include:

- structured evidence delimiters
- explicit instruction/evidence separation
- no direct model tool authority
- bounded evidence selection
- schema validation
- deterministic downstream policy
- rendering model output as untrusted text

No prompt technique alone is considered a security boundary.

That last line is load-bearing and the implementation is built to match it. Three
defenses exist, in descending order of the weight they carry:

1. Structural separation and a nonce-delimited fence, as above.
2. Bounded size: 512 characters per field, 24,000 for the block, so volume alone
   cannot push instructions out of context.
3. Pattern detection of instruction-shaped telemetry.

The third is a signal, not a boundary. It exists so that an intruder writing
"ignore previous instructions" into a filename reaches an analyst as a finding,
because that attempt is itself worth knowing about. It is surfaced on the
`AnalysisOutcome` and recorded in the audit payload rather than being silently
dropped. `evaluation/adversarial-telemetry.json` deliberately keeps cases the
patterns cannot catch — a bidirectional override, zero-width-split tokens, a
paraphrased override with none of the trigger words, and pure volume — so the
corpus does not degenerate into a mirror of the pattern list. The committed
threshold requires every case marked detectable to be detected, and structural
containment for all of them, including the undetectable ones.

## Output validation

Structured AI outputs must be validated against Pydantic/JSON schemas. Invalid responses are rejected or reprocessed within bounded retry limits. Free-form text must never be parsed into privileged shell or firewall commands.

Implemented in `apps/api/privashield_api/ai/validation.py`, and schema validation
is only the first half of it. Shape is not the problem: a response can satisfy
`AIThreatAnalysis` exactly and still claim it blocked an address, cite an event
that was never supplied, or repeat an instruction planted in a filename. Those are
contract violations, and they are refused:

- a claim that an action was taken, since ADR-0001 gives the model no path to
  enforcement, so such a claim is either a hallucination or a sign it followed
  injected instructions. The check targets the claim and not the verb — "blocked
  the host" is refused, "recommend blocking the host" is not, because a detector
  that refused proposals would refuse the only thing the model is for
- an event identifier absent from the supplied telemetry. Paraphrase is
  legitimate; inventing a UUID is not, and it is the one grounding failure that
  can be checked mechanically
- an echo of instruction-shaped telemetry, or of the prompt delimiter
- control or format characters, which can hide content from a reader

Validation runs before anything reaches the audit ledger, because the ledger is
append-only and hash-chained: a bad entry cannot be removed later without
breaking the chain that proves nothing was removed. A refusal is itself recorded,
as `ai.analysis.rejected` with every violation named. Recording only successes
would leave no trace that the model returned something outside its authority,
which is precisely what an investigation needs.

There is no retry. A response that breaks the contract is refused and the request
fails with 502; re-prompting a model that just ignored its instructions is not
obviously safer than not.

## Evaluation

Each production candidate model/profile should be evaluated for:

- classification precision/recall by supported category
- false-positive/false-negative behavior on security tasks
- prompt-injection robustness
- hallucinated remediation frequency
- output-schema compliance
- latency and resource consumption
- sensitive-data echo behavior
- regression against a fixed test corpus

## Provenance

Every persisted model-derived security result should record:

- provider
- model identity/version/digest
- prompt-template version
- relevant generation parameters
- evidence references
- output schema version
- validation state
- output hash

## Model acquisition

Model binaries/weights are supply-chain inputs. Document source, license, digest, and acquisition process. Hardened releases should pin known model identifiers and verify digests where the runtime permits.

## Resource governance

Inference is asynchronous and quota controlled. Configure:

- maximum concurrent jobs
- queue depth
- context/token limits
- request timeout
- retry policy
- CPU/GPU/memory constraints

Threat actors must not be able to create unbounded inference cost from arbitrary event volume.

## Human review

High-impact AI findings should expose enough evidence for analysts to verify the conclusion. User feedback such as confirmed/false-positive classifications may be stored separately and must not silently retrain models without an explicit training workflow.

## Model changes

A model upgrade is a behavior change. Before changing the default model/profile, run the evaluation suite, document regression results, and record the change in release notes.
