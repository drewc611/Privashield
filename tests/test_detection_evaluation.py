from pathlib import Path

from privashield_api.evaluation import evaluate_corpus, load_json, threshold_violations


def test_versioned_detection_corpus_meets_regression_thresholds() -> None:
    corpus = load_json(Path("evaluation/detection-corpus.json"))
    thresholds = load_json(Path("evaluation/thresholds.json"))

    report = evaluate_corpus(corpus)
    violations = threshold_violations(report, thresholds)

    assert report["total_cases"] == 16
    assert report["failed"] == 0
    assert report["pass_rate"] == 1.0
    assert violations == []


def test_evaluation_report_exposes_per_engine_metrics() -> None:
    corpus = load_json(Path("evaluation/detection-corpus.json"))
    report = evaluate_corpus(corpus)

    assert set(report["engines"]) == {
        "dlp",
        "malware",
        "ransomware",
        "anomaly",
        "correlation",
    }
    for summary in report["engines"].values():
        assert summary["cases"] > 0
        assert 0.0 <= summary["pass_rate"] <= 1.0
