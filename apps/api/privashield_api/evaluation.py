from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .anomaly import AnomalyEngine
from .correlation import correlate_events
from .dlp import classify_text
from .malware import assess_file_risk
from .ransomware import assess_ransomware
from .schemas import FileRiskRequest, IdentityObservation, RansomwareObservation, SecurityEvent

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_CORPUS = _REPO_ROOT / "evaluation" / "detection-corpus.json"
_DEFAULT_THRESHOLDS = _REPO_ROOT / "evaluation" / "thresholds.json"


def _score_errors(actual: float, expected: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    minimum = expected.get("min_score")
    maximum = expected.get("max_score")
    if minimum is not None and actual < float(minimum):
        errors.append(f"score {actual:.3f} is below minimum {float(minimum):.3f}")
    if maximum is not None and actual > float(maximum):
        errors.append(f"score {actual:.3f} exceeds maximum {float(maximum):.3f}")
    return errors


def _case_result(case_id: str, errors: list[str]) -> dict[str, Any]:
    return {"id": case_id, "passed": not errors, "errors": errors}


def _evaluate_dlp(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for case in cases:
        request = case["request"]
        expected = case["expect"]
        actual = classify_text(request["text"], request["permission_tier"])
        errors: list[str] = []
        if actual.sensitivity != expected["sensitivity"]:
            errors.append(
                f"sensitivity {actual.sensitivity!r} != {expected['sensitivity']!r}"
            )
        missing_labels = set(expected.get("labels_contains", [])) - set(actual.labels)
        if missing_labels:
            errors.append(f"missing labels: {sorted(missing_labels)}")
        for value in expected.get("redacted_absent", []):
            if value in actual.redacted_text:
                errors.append(f"redaction still contains protected value: {value!r}")
        results.append(_case_result(case["id"], errors))
    return results


def _evaluate_malware(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for case in cases:
        expected = case["expect"]
        actual = assess_file_risk(FileRiskRequest.model_validate(case["request"]))
        errors = _score_errors(actual.risk_score, expected)
        expected_classification = expected.get("classification")
        if expected_classification and actual.classification != expected_classification:
            errors.append(
                f"classification {actual.classification!r} != {expected_classification!r}"
            )
        results.append(_case_result(case["id"], errors))
    return results


def _evaluate_ransomware(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for case in cases:
        expected = case["expect"]
        actual = assess_ransomware(RansomwareObservation.model_validate(case["request"]))
        errors = _score_errors(actual.risk_score, expected)
        allowed = set(expected.get("severity_in", []))
        if allowed and actual.severity.value not in allowed:
            errors.append(f"severity {actual.severity.value!r} not in {sorted(allowed)}")
        results.append(_case_result(case["id"], errors))
    return results


def _evaluate_anomaly(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for case in cases:
        engine = AnomalyEngine()
        actual = None
        for raw_observation in case["observations"]:
            actual = engine.evaluate(IdentityObservation.model_validate(raw_observation))
        if actual is None:
            results.append(_case_result(case["id"], ["sequence has no observations"]))
            continue

        expected = case["expect"]
        errors = _score_errors(actual.risk_score, expected)
        allowed = set(expected.get("severity_in", []))
        if allowed and actual.severity.value not in allowed:
            errors.append(f"severity {actual.severity.value!r} not in {sorted(allowed)}")
        results.append(_case_result(case["id"], errors))
    return results


def _evaluate_correlation(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for case in cases:
        events = [SecurityEvent.model_validate(raw_event) for raw_event in case["events"]]
        actual = correlate_events(
            events,
            max_time_gap_seconds=int(case.get("max_time_gap_seconds", 900)),
        )
        expected = case["expect"]
        errors: list[str] = []
        expected_count = int(expected["incident_count"])
        if len(actual.incidents) != expected_count:
            errors.append(
                f"incident count {len(actual.incidents)} != expected {expected_count}"
            )
        if actual.incidents and expected_count:
            incident = actual.incidents[0]
            minimum_sources = expected.get("min_source_count")
            if minimum_sources is not None and incident.source_count < int(minimum_sources):
                errors.append(
                    f"source count {incident.source_count} is below {int(minimum_sources)}"
                )
            expected_indicators = set(expected.get("indicator_types_contains", []))
            actual_indicators = {item.indicator_type for item in incident.shared_indicators}
            missing = expected_indicators - actual_indicators
            if missing:
                errors.append(f"missing indicator types: {sorted(missing)}")
        results.append(_case_result(case["id"], errors))
    return results


def _engine_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    passed = sum(1 for result in results if result["passed"])
    failed = total - passed
    failures = [result for result in results if not result["passed"]]
    return {
        "cases": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round(passed / total, 4) if total else 0.0,
        "failures": failures,
    }


def evaluate_corpus(corpus: dict[str, Any]) -> dict[str, Any]:
    engine_results = {
        "dlp": _evaluate_dlp(corpus.get("dlp", [])),
        "malware": _evaluate_malware(corpus.get("malware", [])),
        "ransomware": _evaluate_ransomware(corpus.get("ransomware", [])),
        "anomaly": _evaluate_anomaly(corpus.get("anomaly_sequences", [])),
        "correlation": _evaluate_correlation(corpus.get("correlation", [])),
    }
    engines = {name: _engine_summary(results) for name, results in engine_results.items()}
    total = sum(summary["cases"] for summary in engines.values())
    passed = sum(summary["passed"] for summary in engines.values())
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "corpus_schema_version": corpus.get("schema_version"),
        "total_cases": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": round(passed / total, 4) if total else 0.0,
        "engines": engines,
    }


def threshold_violations(
    report: dict[str, Any], thresholds: dict[str, Any]
) -> list[str]:
    violations: list[str] = []
    overall_minimum = float(thresholds.get("overall_min_pass_rate", 0.0))
    if float(report["pass_rate"]) < overall_minimum:
        violations.append(
            f"overall pass rate {report['pass_rate']:.4f} below threshold {overall_minimum:.4f}"
        )

    engine_thresholds = thresholds.get("engine_min_pass_rate", {})
    for engine_name, minimum in engine_thresholds.items():
        summary = report["engines"].get(engine_name)
        if summary is None:
            violations.append(f"required engine {engine_name!r} is missing from report")
            continue
        minimum_value = float(minimum)
        if float(summary["pass_rate"]) < minimum_value:
            violations.append(
                f"{engine_name} pass rate {summary['pass_rate']:.4f} "
                f"below threshold {minimum_value:.4f}"
            )
    return violations


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _human_output(report: dict[str, Any], violations: list[str]) -> str:
    lines = [
        "PrivaShield detection regression benchmark",
        f"Cases: {report['passed']}/{report['total_cases']} passed "
        f"({report['pass_rate']:.1%})",
    ]
    for engine_name, summary in report["engines"].items():
        lines.append(
            f"- {engine_name}: {summary['passed']}/{summary['cases']} "
            f"({summary['pass_rate']:.1%})"
        )
        for failure in summary["failures"]:
            lines.append(f"  - FAIL {failure['id']}: {'; '.join(failure['errors'])}")
    if violations:
        lines.append("Threshold violations:")
        lines.extend(f"- {violation}" for violation in violations)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate PrivaShield deterministic detectors")
    parser.add_argument("--corpus", type=Path, default=_DEFAULT_CORPUS)
    parser.add_argument("--thresholds", type=Path, default=_DEFAULT_THRESHOLDS)
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--enforce-thresholds", action="store_true")
    args = parser.parse_args()

    corpus = load_json(args.corpus)
    thresholds = load_json(args.thresholds)
    report = evaluate_corpus(corpus)
    violations = threshold_violations(report, thresholds)

    if args.json_output:
        print(json.dumps({"report": report, "threshold_violations": violations}, indent=2))
    else:
        print(_human_output(report, violations))

    if args.enforce_thresholds and violations:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
