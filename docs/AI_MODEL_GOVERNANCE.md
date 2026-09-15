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

## Prompt management

Prompts are versioned artifacts. Prompts must:

- distinguish system instructions from untrusted evidence
- identify telemetry as data, never instructions
- request schema-constrained output where possible
- avoid embedding unnecessary sensitive content
- define uncertainty behavior

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

## Output validation

Structured AI outputs must be validated against Pydantic/JSON schemas. Invalid responses are rejected or reprocessed within bounded retry limits. Free-form text must never be parsed into privileged shell or firewall commands.

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
