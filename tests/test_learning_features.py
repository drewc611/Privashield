from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from privashield_api.learning.features import (
    HASH_DIMENSION,
    MAX_SUMMARY_TOKENS,
    extract_features,
    feature_names,
    hash_to_dense,
)
from privashield_api.schemas import Direction, EventSource, SecurityEvent, Severity


def event(**overrides: object) -> SecurityEvent:
    defaults: dict[str, object] = {
        "timestamp": datetime(2026, 9, 23, 14, 30, tzinfo=UTC),
        "source": EventSource.SURICATA,
        "event_type": "alert",
        "severity": Severity.HIGH,
        "summary": "Suspicious outbound TLS pattern",
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Determinism — the detection benchmark depends on it
# --------------------------------------------------------------------------


def test_extraction_is_deterministic_for_the_same_event() -> None:
    subject = event()
    assert extract_features(subject) == extract_features(subject)


def test_extraction_is_stable_across_equal_events() -> None:
    shared_id = uuid4()
    first = event(id=shared_id, src_ip="192.0.2.10", user_id="alice")
    second = event(id=shared_id, src_ip="192.0.2.10", user_id="alice")
    assert extract_features(first) == extract_features(second)


def test_feature_names_do_not_depend_on_process_hash_seed() -> None:
    # Regression guard: a previous design using the built-in hash() would have
    # produced different bucket names in each interpreter process, silently
    # invalidating any persisted weights on restart.
    features = extract_features(event(user_id="alice"))
    hashed = [name for name in features if name.startswith("user#")]
    assert hashed == ["user#476"], hashed


# --------------------------------------------------------------------------
# Privacy — raw identifiers must never become feature names
# --------------------------------------------------------------------------


def test_raw_identifiers_never_appear_in_feature_names() -> None:
    subject = event(
        src_ip="198.51.100.77",
        dst_ip="203.0.113.9",
        user_id="finance.director@example.com",
        process="/usr/local/bin/exfil-tool",
        summary="Credential dump written to /home/alice/secrets.txt",
    )
    names = " ".join(extract_features(subject))
    for secret in (
        "198.51.100.77",
        "203.0.113.9",
        "finance.director",
        "example.com",
        "exfil-tool",
        "alice",
        "secrets",
    ):
        assert secret not in names, f"raw value {secret!r} leaked into feature names"


def test_distinct_identifiers_produce_distinct_buckets() -> None:
    # Hashing must not be so lossy that every user collapses together, or the
    # model cannot learn per-entity behaviour at all.
    buckets = {
        next(name for name in extract_features(event(user_id=user)) if name.startswith("user#"))
        for user in ("alice", "bob", "carol", "dave", "erin")
    }
    assert len(buckets) >= 4


# --------------------------------------------------------------------------
# Boundedness — the model must not grow without limit
# --------------------------------------------------------------------------


def test_hashed_buckets_stay_within_the_configured_dimension() -> None:
    names: set[str] = set()
    for index in range(400):
        names |= feature_names(
            [event(user_id=f"user-{index}", src_ip=f"10.0.{index // 256}.{index % 256}")]
        )
    for name in names:
        if "#" in name:
            namespace, bucket = name.split("#")
            assert 0 <= int(bucket) < HASH_DIMENSION, f"{namespace} bucket out of range"


def test_summary_token_count_is_capped() -> None:
    # A long attacker-controlled summary must not be able to flood the vector.
    # Stay inside the schema's own 4096-character summary limit; the point is
    # the token cap, not the length cap.
    long_summary = " ".join(f"t{index}" for index in range(400))
    features = extract_features(event(summary=long_summary))
    summary_features = [name for name in features if name.startswith("summary#")]
    assert len(summary_features) <= MAX_SUMMARY_TOKENS


def test_summary_contributions_sum_to_one() -> None:
    features = extract_features(event(summary="alpha beta gamma delta"))
    total = sum(value for name, value in features.items() if name.startswith("summary#"))
    assert abs(total - 1.0) < 1e-9


# --------------------------------------------------------------------------
# Signal — the features have to actually carry meaning
# --------------------------------------------------------------------------


def test_severity_is_ordinal_and_monotonic() -> None:
    scores = [
        extract_features(event(severity=level))["severity_ordinal"]
        for level in (
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        )
    ]
    assert scores == sorted(scores)
    assert scores[0] == 0.0
    assert scores[-1] == 1.0


def test_notable_ports_are_named_rather_than_hashed() -> None:
    features = extract_features(event(dst_port=3389))
    assert features["dst_port_rdp"] == 1.0
    assert features["dst_port_registered"] == 1.0


def test_port_classes_partition_the_range() -> None:
    assert "dst_port_wellknown" in extract_features(event(dst_port=80))
    assert "dst_port_registered" in extract_features(event(dst_port=8080))
    assert "dst_port_ephemeral" in extract_features(event(dst_port=54321))
    assert "dst_port_absent" in extract_features(event(dst_port=None))


def test_hour_of_day_is_cyclical() -> None:
    late = extract_features(event(timestamp=datetime(2026, 9, 23, 23, 30, tzinfo=UTC)))
    early = extract_features(event(timestamp=datetime(2026, 9, 24, 0, 30, tzinfo=UTC)))
    # An hour apart across midnight should be close in the cyclical encoding.
    distance = abs(late["hour_sin"] - early["hour_sin"]) + abs(late["hour_cos"] - early["hour_cos"])
    assert distance < 0.3


def test_weekend_flag_tracks_the_calendar() -> None:
    saturday = extract_features(event(timestamp=datetime(2026, 9, 26, 12, 0, tzinfo=UTC)))
    wednesday = extract_features(event(timestamp=datetime(2026, 9, 23, 12, 0, tzinfo=UTC)))
    assert saturday["is_weekend"] == 1.0
    assert wednesday["is_weekend"] == 0.0


def test_direction_absence_is_itself_a_feature() -> None:
    assert "direction_absent" in extract_features(event(direction=None))
    assert "direction_outbound" in extract_features(event(direction=Direction.OUTBOUND))


def test_presence_flags_reflect_populated_fields() -> None:
    sparse = extract_features(event())
    rich = extract_features(event(user_id="alice", process="bash", asset_id=uuid4()))
    assert sparse["has_user"] == 0.0
    assert rich["has_user"] == 1.0
    assert rich["has_process"] == 1.0
    assert rich["has_asset"] == 1.0


# --------------------------------------------------------------------------
# Dense projection for the neural network
# --------------------------------------------------------------------------


def test_dense_projection_has_the_requested_width() -> None:
    dense = hash_to_dense(extract_features(event()), 64)
    assert len(dense) == 64


def test_dense_projection_is_deterministic() -> None:
    features = extract_features(event(user_id="alice"))
    assert hash_to_dense(features, 128) == hash_to_dense(features, 128)


def test_dense_projection_uses_signed_hashing() -> None:
    # Signed hashing is what keeps collisions cancelling instead of compounding,
    # so both signs must actually occur across a realistic feature set.
    dense = hash_to_dense(extract_features(event(user_id="alice", process="bash")), 256)
    assert any(value > 0 for value in dense)
    assert any(value < 0 for value in dense)


def test_different_events_project_differently() -> None:
    benign = hash_to_dense(extract_features(event(severity=Severity.INFO, dst_port=443)), 128)
    hostile = hash_to_dense(extract_features(event(severity=Severity.CRITICAL, dst_port=4444)), 128)
    assert benign != hostile
