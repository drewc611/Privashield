# Detection Evaluation and Regression Thresholds

PrivaShield uses a versioned deterministic evaluation corpus to prevent rule and correlation changes from silently degrading known detection behavior.

This is a regression-quality gate, not a claim of real-world detection efficacy, certification, production readiness, or statistically representative benchmark performance.

## What is evaluated

The current corpus covers five deterministic surfaces:

| Engine | Current evaluation focus |
| --- | --- |
| DLP | benign text, email detection, restricted identifiers, redaction behavior, invalid payment-card rejection |
| Identity anomaly | baseline login, impossible travel, single large download, ten-minute download burst |
| Ransomware | idle baseline, mass-encryption pattern, rename-heavy low-risk activity |
| File risk | safe document, disguised executable, local signature match, script extension |
| Incident correlation | cross-source shared asset, same-source rejection, correlation-window rejection, three-source shared user |

The corpus lives at `evaluation/corpus/detection-v1.json` and contains explicit expected outcomes for every case.

## Versioning

The corpus has two independent version fields:

- `schema_version` controls the JSON contract understood by the runner.
- `corpus_version` identifies the curated expected-outcome set.

When an intentional rule change alters a known expected outcome, update the implementation, tests, corpus expectation, corpus version, and review rationale together. Do not silently weaken thresholds to make a regression pass.

## Metrics

The runner calculates:

- total case count;
- passed case count;
- overall pass rate;
- per-engine case count;
- per-engine passed count;
- per-engine pass rate;
- whether overall and per-engine minimum thresholds are met.

The initial deterministic corpus requires a `1.0` pass rate overall and for every engine. These thresholds are appropriate for a curated regression corpus because each case encodes behavior the repository explicitly expects to remain stable.

This metric should not be confused with precision, recall, false-positive rate, or field detection efficacy on a representative external dataset. Those require a larger labeled corpus with a sampling methodology appropriate to those claims.

## Running the benchmark

After installing development dependencies:

```bash
make benchmark
```

or:

```bash
python scripts/run_detection_benchmarks.py
```

For machine-readable output:

```bash
python scripts/run_detection_benchmarks.py --json
```

The command exits non-zero when an overall or per-engine regression threshold is missed.

## CI behavior

`tests/test_detection_evaluation.py` runs the same corpus through Pytest. Because the existing CI executes the full Pytest suite, detection-regression thresholds are enforced without introducing a separate privileged workflow.

The tests also mutate a known-good case in a temporary corpus and verify that the benchmark reports a failed threshold. This checks the benchmark harness itself rather than only the detector implementations.

## Safety and privacy properties

The evaluation corpus is synthetic and intentionally contains no customer, production, secret, or live packet data.

The benchmark does not:

- enable firewall or packet enforcement;
- invoke privileged host/network actions;
- change AI authority;
- call external model providers;
- require internet access;
- persist sensitive telemetry;
- publish evaluation results externally.

Correlation cases continue to verify non-enforcing behavior. Ransomware cases explicitly verify `enforced=false` where applicable.

## Adding cases

A new case should be added when:

- a bug is fixed and should never recur;
- a new deterministic detection rule is introduced;
- a boundary or negative case needs durable coverage;
- an analyst-confirmed behavior is promoted into a stable regression expectation;
- correlation logic gains a new evidence relationship.

Every case needs a unique ID, supported engine, input object, and expected object. Prefer minimal synthetic examples that isolate one behavior.

## Future extensions

Useful future additions include:

- larger labeled benign/malicious datasets;
- precision, recall, F1, and class-specific false-positive metrics;
- confidence calibration evaluation;
- analyst-feedback-derived holdout sets;
- model-version comparison for advisory AI outputs;
- performance/latency characterization;
- reproducible benchmark result artifacts tied to release candidates.

Those extensions should remain separate from privileged enforcement qualification and should not be represented as production effectiveness until the underlying dataset and methodology justify that claim.
