# Detection Evaluation and Regression Harness

PrivaShield includes a versioned deterministic regression corpus and benchmark harness for its local rule-based detection components.

The harness is a **software-quality regression control**. It is not a claim of production detection efficacy, zero-day coverage, sensitivity/specificity, or performance against representative real-world threat populations.

## Covered engines

The current corpus covers:

- DLP classification and redaction
- file-risk / malware heuristics
- ransomware behavior scoring
- identity anomaly scoring
- cross-sensor incident correlation

Each engine includes positive and negative examples where practical.

## Files

```text
evaluation/
├── detection-corpus.json
└── thresholds.json
```

`detection-corpus.json` contains versioned inputs and expected outcomes.

`thresholds.json` defines the minimum pass rate required for the corpus overall and for each engine.

The evaluator lives at:

```text
apps/api/privashield_api/evaluation.py
```

## Run locally

After installing the development dependencies:

```bash
python -m privashield_api.evaluation
```

Machine-readable output:

```bash
python -m privashield_api.evaluation --json
```

Enforce configured thresholds:

```bash
python -m privashield_api.evaluation --enforce-thresholds
```

The threshold-enforcement command exits non-zero when the overall or per-engine pass rate falls below the configured baseline.

## CI behavior

The normal CI workflow runs the evaluator with threshold enforcement after the Python test suite.

A detector or correlation-rule change therefore must preserve the committed expected behavior or intentionally update the corpus and thresholds in the same reviewed change.

Any threshold reduction should include:

- the reason for the change;
- cases affected;
- security impact;
- false-positive / false-negative implications;
- rollback plan.

Thresholds must not be lowered merely to make CI pass.

## Current metrics

The harness reports:

- total cases;
- passed and failed cases;
- overall pass rate;
- per-engine case count;
- per-engine pass/fail count;
- per-engine pass rate;
- failed case IDs and expectation errors.

These are regression metrics against the committed corpus, not precision, recall, ROC/AUC, or field efficacy measurements.

## Corpus governance

New detector behavior should add representative cases before or with implementation changes.

Good corpus additions include:

- a positive case the detector is expected to flag;
- a closely related negative case it should not flag;
- a boundary case near the relevant threshold;
- a previously observed regression reduced to a minimal non-sensitive fixture.

Do not commit real customer data, production packet payloads, live credentials, PHI, or other unnecessary sensitive information to the corpus. Use synthetic fixtures.

## Future evaluation maturity

This baseline should be expanded with:

- larger synthetic and licensed/public datasets;
- precision and recall measurement where ground truth is available;
- detector-specific false-positive budgets;
- performance/latency benchmarks;
- model-version evaluation for local AI components;
- drift tracking across releases;
- signed evaluation artifacts for release qualification.
