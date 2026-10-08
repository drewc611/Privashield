"""Tests for the coverage gate itself.

A gate nobody tests is a gate that silently stops working, which is exactly what
happened here: `pytest --cov-fail-under` printed "FAIL Required test coverage of
85.97% not reached" and exited 0, because it chose the message from the unrounded
percentage and the exit code from the rounded one. `make verify` then reported
every gate passing.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "check_coverage", Path(".github/scripts/check_coverage.py")
)
assert _SPEC is not None and _SPEC.loader is not None
check_coverage = importlib.util.module_from_spec(_SPEC)
sys.modules["check_coverage"] = check_coverage
_SPEC.loader.exec_module(check_coverage)

attainable_floor = check_coverage.attainable_floor
meets_floor = check_coverage.meets_floor


# --------------------------------------------------------------------------
# The boundary this gate exists to close
# --------------------------------------------------------------------------


def test_a_floor_one_rounding_step_above_actual_is_refused() -> None:
    """The exact shape of the bug: 85.969616% does not meet 85.97%.

    Both render as "85.97" at two decimals, which is why comparing rendered
    values let this through.
    """
    assert meets_floor(85.969616, 85.97) is False


def test_the_same_measurement_meets_the_floor_below_it() -> None:
    assert meets_floor(85.969616, 85.96) is True


@pytest.mark.parametrize(
    ("actual", "floor", "expected"),
    [
        (85.0, 85.0, True),  # exactly on the floor clears it
        (84.999999, 85.0, False),  # a hair under does not
        (100.0, 100.0, True),
        (0.0, 0.0, True),
        (85.969616, 90.0, False),  # a real drop
    ],
)
def test_comparison_is_at_full_precision(actual: float, floor: float, expected: bool) -> None:
    assert meets_floor(actual, floor) is expected


# --------------------------------------------------------------------------
# Ratcheting advice must be attainable, or it recreates the bug
# --------------------------------------------------------------------------


def test_the_suggested_floor_is_always_attainable() -> None:
    # Copying the displayed value is the natural way to ratchet a floor, and the
    # displayed value is rounded, so the suggestion has to be floored instead.
    for actual in (85.969616, 85.97, 85.9700001, 0.004, 99.999):
        suggested = attainable_floor(actual)
        assert meets_floor(actual, suggested), f"{suggested} unattainable from {actual}"


def test_the_suggested_floor_keeps_two_decimals() -> None:
    assert attainable_floor(85.969616) == 85.96
    assert attainable_floor(85.9) == 85.9
    assert attainable_floor(100.0) == 100.0


def test_the_suggestion_never_rounds_up_past_the_measurement() -> None:
    for actual in (85.999, 85.995, 85.991):
        assert attainable_floor(actual) <= actual
