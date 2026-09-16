from __future__ import annotations

import json
from pathlib import Path

from privashield_api.evaluation import load_corpus, run_evaluation

CORPUS = Path("evaluation/corpus/detection-v1.json")
EXPECTED_ENGINES = {"dlp", "anomaly", "ransomware", "file_risk", "correlation"}


def test_detection_corpus_meets_all_regression_thresholds() -> None:
    report = run_evaluation(CORPUS)

    assert report.passed, json.dumps(report.to_dict(), indent=2, sort_keys=True)
    assert report.overall_pass_rate == 1.0
    assert set(report.engine_metrics) == EXPECTED_ENGINES
    assert all(metric.threshold_met for metric in report.engine_metrics.values())


def test_detection_corpus_has_stable_unique_case_ids() -> None:
    corpus = load_corpus(CORPUS)
    case_ids = [case["id"] for case in corpus["cases"]]

    assert corpus["schema_version"] == "1.0"
    assert corpus["corpus_version"] == "2026.09.1"
    assert len(case_ids) == len(set(case_ids))
    assert {case["engine"] for case in corpus["cases"]} == EXPECTED_ENGINES


def test_benchmark_reports_threshold_regression(tmp_path: Path) -> None:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    target = next(case for case in corpus["cases"] if case["id"] == "dlp-benign-text")
    target["expected"]["sensitivity"] = "restricted"
    modified = tmp_path / "regressed-corpus.json"
    modified.write_text(json.dumps(corpus), encoding="utf-8")

    report = run_evaluation(modified)

    assert report.passed is False
    assert report.overall_pass_rate < report.minimum_overall_pass_rate
    assert report.engine_metrics["dlp"].threshold_met is False
    failed = next(case for case in report.cases if case.case_id == "dlp-benign-text")
    assert any("sensitivity expected restricted" in failure for failure in failed.failures)
