from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .anomaly import AnomalyEngine
from .correlation import correlate_events
from .dlp import classify_text
from .malware import assess_file_risk
from .ransomware import assess_ransomware
from .schemas import FileRiskRequest, IdentityObservation, RansomwareObservation, SecurityEvent

DEFAULT_CORPUS_PATH = (
    Path(__file__).resolve().parents[3] / "evaluation" / "corpus" / "detection-v1.json"
)
SUPPORTED_ENGINES = {"dlp", "anomaly", "ransomware", "file_risk", "correlation"}


@dataclass(frozen=True)
class EvaluationCaseResult:
    case_id: str
    engine: str
    passed: bool
    failures: list[str]


@dataclass(frozen=True)
class EngineMetrics:
    engine: str
    total: int
    passed: int
    pass_rate: float
    minimum_pass_rate: float
    threshold_met: bool


@dataclass(frozen=True)
class EvaluationReport:
    corpus_version: str
    generated_at: str
    total_cases: int
    passed_cases: int
    overall_pass_rate: float
    minimum_overall_pass_rate: float
    threshold_met: bool
    engine_metrics: dict[str, EngineMetrics]
    cases: list[EvaluationCaseResult]

    @property
    def passed(self) -> bool:
        return self.threshold_met and all(metric.threshold_met for metric in self.engine_metrics.values())

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["passed"] = self.passed
        return value


def load_corpus(path: str | Path = DEFAULT_CORPUS_PATH) -> dict[str, Any]:
    corpus_path = Path(path)
    payload = json.loads(corpus_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "1.0":
        raise ValueError("unsupported evaluation corpus schema_version")
    if not payload.get("corpus_version"):
        raise ValueError("evaluation corpus must define corpus_version")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("evaluation corpus must contain at least one case")

    seen: set[str] = set()
    for case in cases:
        case_id = case.get("id")
        engine = case.get("engine")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("each evaluation case must define a non-empty id")
        if case_id in seen:
            raise ValueError(f"duplicate evaluation case id: {case_id}")
        seen.add(case_id)
        if engine not in SUPPORTED_ENGINES:
            raise ValueError(f"unsupported evaluation engine for {case_id}: {engine}")
        if not isinstance(case.get("input"), dict):
            raise ValueError(f"evaluation case {case_id} must define input")
        if not isinstance(case.get("expected"), dict):
            raise ValueError(f"evaluation case {case_id} must define expected")
    return payload


def _compare_score(actual: float, expected: dict[str, Any], failures: list[str]) -> None:
    if "risk_score" in expected:
        tolerance = float(expected.get("score_tolerance", 1e-6))
        target = float(expected["risk_score"])
        if abs(actual - target) > tolerance:
            failures.append(f"risk_score expected {target}±{tolerance}, got {actual}")
    if "min_risk_score" in expected and actual < float(expected["min_risk_score"]):
        failures.append(f"risk_score expected >= {expected['min_risk_score']}, got {actual}")
    if "max_risk_score" in expected and actual > float(expected["max_risk_score"]):
        failures.append(f"risk_score expected <= {expected['max_risk_score']}, got {actual}")


def _expect_contains(actual: list[str], expected: list[str], label: str, failures: list[str]) -> None:
    for item in expected:
        if not any(item in value for value in actual):
            failures.append(f"{label} missing expected fragment: {item}")


def _evaluate_dlp(case: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    request = case["input"]
    expected = case["expected"]
    result = classify_text(request["text"], request.get("permission_tier", "internal"))

    if result.sensitivity != expected.get("sensitivity"):
        failures.append(
            f"sensitivity expected {expected.get('sensitivity')}, got {result.sensitivity}"
        )
    if "labels" in expected and sorted(result.labels) != sorted(expected["labels"]):
        failures.append(f"labels expected {sorted(expected['labels'])}, got {sorted(result.labels)}")
    if "redacted" in expected:
        was_redacted = result.redacted_text != request["text"]
        if was_redacted is not bool(expected["redacted"]):
            failures.append(f"redacted expected {expected['redacted']}, got {was_redacted}")
    for marker in expected.get("redaction_markers", []):
        if marker not in result.redacted_text:
            failures.append(f"redacted_text missing marker: {marker}")
    return failures


def _evaluate_anomaly(case: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    engine = AnomalyEngine()
    request = case["input"]
    observations = request.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError("anomaly case requires a non-empty observations list")

    result = None
    for observation in observations:
        result = engine.evaluate(IdentityObservation.model_validate(observation))
    assert result is not None
    expected = case["expected"]
    if result.severity.value != expected.get("severity"):
        failures.append(f"severity expected {expected.get('severity')}, got {result.severity.value}")
    _compare_score(result.risk_score, expected, failures)
    _expect_contains(result.reasons, expected.get("reason_contains", []), "reasons", failures)
    return failures


def _evaluate_ransomware(case: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    result = assess_ransomware(RansomwareObservation.model_validate(case["input"]))
    expected = case["expected"]
    if result.severity.value != expected.get("severity"):
        failures.append(f"severity expected {expected.get('severity')}, got {result.severity.value}")
    _compare_score(result.risk_score, expected, failures)
    _expect_contains(result.reasons, expected.get("reason_contains", []), "reasons", failures)
    if "enforced" in expected and result.enforced is not bool(expected["enforced"]):
        failures.append(f"enforced expected {expected['enforced']}, got {result.enforced}")
    return failures


def _evaluate_file_risk(case: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    result = assess_file_risk(FileRiskRequest.model_validate(case["input"]))
    expected = case["expected"]
    if result.severity.value != expected.get("severity"):
        failures.append(f"severity expected {expected.get('severity')}, got {result.severity.value}")
    if result.classification != expected.get("classification"):
        failures.append(
            f"classification expected {expected.get('classification')}, got {result.classification}"
        )
    _compare_score(result.risk_score, expected, failures)
    _expect_contains(result.indicators, expected.get("indicator_contains", []), "indicators", failures)
    return failures


def _evaluate_correlation(case: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    request = case["input"]
    events = [SecurityEvent.model_validate(value) for value in request.get("events", [])]
    result = correlate_events(
        events,
        max_time_gap_seconds=int(request.get("max_time_gap_seconds", 900)),
    )
    expected = case["expected"]
    expected_count = int(expected.get("incident_count", 0))
    if len(result.incidents) != expected_count:
        failures.append(f"incident_count expected {expected_count}, got {len(result.incidents)}")
        return failures
    if expected_count == 0:
        return failures

    incident = result.incidents[0]
    if "severity" in expected and incident.severity.value != expected["severity"]:
        failures.append(f"severity expected {expected['severity']}, got {incident.severity.value}")
    if "event_count" in expected and incident.event_count != int(expected["event_count"]):
        failures.append(f"event_count expected {expected['event_count']}, got {incident.event_count}")
    if "source_count" in expected and incident.source_count != int(expected["source_count"]):
        failures.append(f"source_count expected {expected['source_count']}, got {incident.source_count}")
    _compare_score(incident.score, expected, failures)
    actual_types = {item.indicator_type for item in incident.shared_indicators}
    for indicator_type in expected.get("indicator_types", []):
        if indicator_type not in actual_types:
            failures.append(f"shared indicators missing type: {indicator_type}")
    if incident.enforced:
        failures.append("correlation result must remain non-enforcing")
    return failures


_EVALUATORS: dict[str, Callable[[dict[str, Any]], list[str]]] = {
    "dlp": _evaluate_dlp,
    "anomaly": _evaluate_anomaly,
    "ransomware": _evaluate_ransomware,
    "file_risk": _evaluate_file_risk,
    "correlation": _evaluate_correlation,
}


def run_evaluation(path: str | Path = DEFAULT_CORPUS_PATH) -> EvaluationReport:
    corpus = load_corpus(path)
    case_results: list[EvaluationCaseResult] = []
    for case in corpus["cases"]:
        failures: list[str]
        try:
            failures = _EVALUATORS[case["engine"]](case)
        except Exception as exc:  # Corpus execution errors are benchmark failures, not silent skips.
            failures = [f"evaluation raised {type(exc).__name__}: {exc}"]
        case_results.append(
            EvaluationCaseResult(
                case_id=case["id"],
                engine=case["engine"],
                passed=not failures,
                failures=failures,
            )
        )

    thresholds = corpus.get("thresholds", {})
    engine_thresholds = thresholds.get("engine_min_pass_rate", {})
    engine_metrics: dict[str, EngineMetrics] = {}
    for engine in sorted({result.engine for result in case_results}):
        engine_cases = [result for result in case_results if result.engine == engine]
        passed = sum(result.passed for result in engine_cases)
        rate = passed / len(engine_cases)
        minimum = float(engine_thresholds.get(engine, 1.0))
        engine_metrics[engine] = EngineMetrics(
            engine=engine,
            total=len(engine_cases),
            passed=passed,
            pass_rate=rate,
            minimum_pass_rate=minimum,
            threshold_met=rate >= minimum,
        )

    passed_cases = sum(result.passed for result in case_results)
    overall_rate = passed_cases / len(case_results)
    overall_minimum = float(thresholds.get("overall_min_pass_rate", 1.0))
    return EvaluationReport(
        corpus_version=corpus["corpus_version"],
        generated_at=datetime.now(UTC).isoformat(),
        total_cases=len(case_results),
        passed_cases=passed_cases,
        overall_pass_rate=overall_rate,
        minimum_overall_pass_rate=overall_minimum,
        threshold_met=overall_rate >= overall_minimum,
        engine_metrics=engine_metrics,
        cases=case_results,
    )
