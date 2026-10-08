#!/usr/bin/env python3
"""Assert the coverage floor against the unrounded measurement.

`pytest --cov-fail-under` cannot be trusted alone at the boundary. It decides the
message it prints from the unrounded percentage but its exit code from the
rounded one, so a floor that sits within a rounding step of actual coverage makes
pytest print "FAIL Required test coverage of 85.97% not reached" and then exit 0.
`make verify` went on to report every gate passing.

That blind spot is narrow — half of one hundredth of a percent — but the natural
way to ratchet a floor is to copy the number the report displays, and the
displayed number is rounded, so the floor lands inside the blind spot by
construction rather than by accident.

This script is the authoritative check: it compares the full-precision value and
says what it compared, so a failure is legible and a pass is real.
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from pathlib import Path


def attainable_floor(actual: float) -> float:
    """The highest two-decimal floor this measurement can actually meet.

    Floored, never rounded. Rounding here would hand back a floor one step above
    the measurement and reintroduce the bug this script exists to close.
    """
    return math.floor(actual * 100) / 100


def meets_floor(actual: float, floor: float) -> bool:
    """Whether coverage clears the floor, compared at full precision.

    Separated out so the boundary can be tested without a coverage run, because
    the boundary is where this went wrong.
    """
    return actual >= floor


def measured_percentage(data_file: Path) -> float:
    """Read total coverage at full precision from the recorded run."""
    report = subprocess.run(
        [sys.executable, "-m", "coverage", "json", "-o", "-", "-q"],
        capture_output=True,
        text=True,
        check=False,
    )
    if report.returncode != 0:
        raise SystemExit(f"could not read coverage data from {data_file}: {report.stderr.strip()}")
    payload = json.loads(report.stdout)
    return float(payload["totals"]["percent_covered"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min", required=True, type=float, help="coverage floor, per cent")
    parser.add_argument("--data-file", default=".coverage", type=Path)
    args = parser.parse_args()

    actual = measured_percentage(args.data_file)
    attainable = attainable_floor(actual)

    if not meets_floor(actual, args.min):
        print(
            f"COVERAGE FAIL: {actual:.6f}% measured, floor is {args.min}%.\n"
            f"  If coverage genuinely dropped, restore it rather than lowering the floor.\n"
            f"  If the floor was set from a rounded display value, the highest\n"
            f"  attainable two-decimal floor for this measurement is {attainable:.2f}.",
            file=sys.stderr,
        )
        return 1

    headroom = actual - args.min
    print(f"Coverage {actual:.6f}% meets the {args.min}% floor (headroom {headroom:.4f} points).")
    if attainable > args.min:
        print(f"  Floor could be ratcheted to {attainable:.2f}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
