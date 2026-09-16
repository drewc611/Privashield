from __future__ import annotations

import argparse
import json
from pathlib import Path

from privashield_api.evaluation import DEFAULT_CORPUS_PATH, run_evaluation


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the versioned PrivaShield deterministic detection regression corpus."
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS_PATH,
        help="Path to the evaluation corpus JSON file.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the complete machine-readable evaluation report.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    report = run_evaluation(args.corpus)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"PrivaShield detection corpus: {report.corpus_version}")
        print(
            "overall: "
            f"{report.passed_cases}/{report.total_cases} "
            f"({report.overall_pass_rate:.1%}) "
            f"threshold={report.minimum_overall_pass_rate:.1%}"
        )
        for engine, metrics in sorted(report.engine_metrics.items()):
            state = "PASS" if metrics.threshold_met else "FAIL"
            print(
                f"{engine}: {metrics.passed}/{metrics.total} "
                f"({metrics.pass_rate:.1%}) threshold={metrics.minimum_pass_rate:.1%} {state}"
            )
        failures = [case for case in report.cases if not case.passed]
        for case in failures:
            for failure in case.failures:
                print(f"FAIL {case.case_id}: {failure}")

    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
