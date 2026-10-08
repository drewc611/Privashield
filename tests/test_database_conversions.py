"""Tests for the ORM-to-domain conversions.

These used to be implicit: the module carried a blanket `arg-type` mypy exclusion
because its annotations claimed enums and addresses while the values were strings,
and Pydantic coerced the difference silently. The point of making them explicit is
not type-checker tidiness — it is that a row outside the domain its column
promises now fails at the boundary, naming the column and the value.
"""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Address
from uuid import uuid4

import pytest

from privashield_api.database import (
    AnalystFeedbackRecord,
    PolicyHistoryRecord,
    PolicyRevisionRecord,
    SecurityEventRecord,
    StoredValueError,
)
from privashield_api.feedback_models import AnalystFeedback, FeedbackLabel, FeedbackTargetType
from privashield_api.policy_models import (
    PolicyDocument,
    PolicyHistoryEvent,
    PolicyHistoryEventType,
    PolicyRevision,
    PolicyStatus,
)
from privashield_api.schemas import Direction, EventSource, SecurityEvent, Severity


def event(**overrides: object) -> SecurityEvent:
    defaults: dict[str, object] = {
        "timestamp": datetime(2026, 10, 8, 12, 0, tzinfo=UTC),
        "source": EventSource.SURICATA,
        "event_type": "alert",
        "severity": Severity.HIGH,
        "summary": "Suspicious outbound TLS",
        "src_ip": "198.51.100.7",
        "dst_ip": "10.0.4.17",
        "direction": Direction.OUTBOUND,
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)  # type: ignore[arg-type]


def stored(subject: SecurityEvent) -> SecurityEventRecord:
    return SecurityEventRecord.from_event(subject)


# --------------------------------------------------------------------------
# A clean round trip must preserve types, not just values
# --------------------------------------------------------------------------


def test_an_event_round_trips_with_its_types_intact() -> None:
    original = event()
    restored = stored(original).to_event()

    assert restored.source is EventSource.SURICATA
    assert restored.severity is Severity.HIGH
    assert restored.direction is Direction.OUTBOUND
    assert restored.src_ip == IPv4Address("198.51.100.7")
    assert restored.summary == original.summary


def test_absent_optional_columns_stay_absent() -> None:
    restored = stored(event(src_ip=None, dst_ip=None, direction=None)).to_event()
    assert restored.src_ip is None
    assert restored.dst_ip is None
    assert restored.direction is None


def test_feedback_round_trips_with_its_enums_intact() -> None:
    subject = AnalystFeedback(
        target_type=FeedbackTargetType.EVENT,
        target_id=uuid4(),
        label=FeedbackLabel.TRUE_POSITIVE,
        identity_verified=True,
    )
    restored = AnalystFeedbackRecord.from_feedback(subject).to_feedback()

    assert restored.target_type is FeedbackTargetType.EVENT
    assert restored.label is FeedbackLabel.TRUE_POSITIVE


# --------------------------------------------------------------------------
# A row outside its column's domain fails where it can be understood
# --------------------------------------------------------------------------


def test_an_unknown_severity_names_the_column_and_the_value() -> None:
    record = stored(event())
    record.severity = "catastrophic"  # written by an older schema, or by hand

    with pytest.raises(StoredValueError) as raised:
        record.to_event()
    message = str(raised.value)
    assert "security_events.severity" in message
    assert "catastrophic" in message
    # And it says what would have been acceptable, so the row can be repaired.
    assert "critical" in message


def test_an_unknown_source_is_refused() -> None:
    record = stored(event())
    record.source = "some-future-sensor"
    with pytest.raises(StoredValueError, match="security_events.source"):
        record.to_event()


def test_an_unknown_direction_is_refused_rather_than_dropped() -> None:
    # Silently nulling it would be worse: a reader cannot tell "no direction
    # recorded" from "direction recorded and discarded".
    record = stored(event())
    record.direction = "sideways"
    with pytest.raises(StoredValueError, match="security_events.direction"):
        record.to_event()


def test_a_malformed_address_is_refused() -> None:
    record = stored(event())
    record.src_ip = "not-an-address"
    with pytest.raises(StoredValueError, match="is not an IP address"):
        record.to_event()


def test_an_unknown_feedback_label_is_refused() -> None:
    subject = AnalystFeedback(
        target_type=FeedbackTargetType.EVENT,
        target_id=uuid4(),
        label=FeedbackLabel.BENIGN,
        identity_verified=True,
    )
    record = AnalystFeedbackRecord.from_feedback(subject)
    record.label = "probably-fine"

    with pytest.raises(StoredValueError, match="analyst_feedback.label"):
        record.to_feedback()


def test_the_failure_is_a_value_error_so_existing_handlers_still_catch_it() -> None:
    # StoredValueError subclasses ValueError on purpose: callers that already
    # guarded against a bad row keep working.
    record = stored(event())
    record.severity = "nonsense"
    with pytest.raises(ValueError):
        record.to_event()


# --------------------------------------------------------------------------
# Policy rows, where a bad conversion has signature consequences
# --------------------------------------------------------------------------


def revision(**overrides: object) -> PolicyRevision:
    defaults: dict[str, object] = {
        "policy_id": uuid4(),
        "version": 1,
        "document": PolicyDocument(
            name="egress-baseline",
            description="Hold outbound response actions behind approval",
        ),
        "key_id": "local-v1",
        "algorithm": "ed25519",
        "signature": "b" * 128,
        "content_digest": "a" * 64,
        "status": PolicyStatus.DRAFT,
        "created_by": "operator",
        "created_at": datetime(2026, 10, 8, 12, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return PolicyRevision(**defaults)  # type: ignore[arg-type]


def test_a_policy_revision_round_trips_with_its_types_intact() -> None:
    original = revision()
    restored = PolicyRevisionRecord.from_revision(original).to_revision()

    assert restored.status is PolicyStatus.DRAFT
    assert restored.algorithm == "ed25519"
    assert isinstance(restored.document, PolicyDocument)
    assert restored.document.name == "egress-baseline"


def test_a_signature_algorithm_this_build_cannot_verify_is_refused() -> None:
    """The sharpest case for converting explicitly.

    Coercing an unknown algorithm would mean verifying a signature with the wrong
    one, and a signature checked with the wrong algorithm is not a checked
    signature. Refusing the row is the only safe reading.
    """
    record = PolicyRevisionRecord.from_revision(revision())
    record.algorithm = "rsa-pkcs1-sha1"

    with pytest.raises(StoredValueError) as raised:
        record.to_revision()
    assert "policy_revisions.algorithm" in str(raised.value)
    assert "this build verifies" in str(raised.value)


def test_an_unknown_policy_status_is_refused() -> None:
    record = PolicyRevisionRecord.from_revision(revision())
    record.status = "half-approved"
    with pytest.raises(StoredValueError, match="policy_revisions.status"):
        record.to_revision()


def test_a_malformed_policy_document_is_refused() -> None:
    record = PolicyRevisionRecord.from_revision(revision())
    record.document_json = {"description": "no name at all"}
    with pytest.raises(StoredValueError, match="valid policy document"):
        record.to_revision()


def test_a_policy_history_event_round_trips() -> None:
    original = PolicyHistoryEvent(
        policy_id=uuid4(),
        version=1,
        event_type=PolicyHistoryEventType.REGISTERED,
        actor="operator",
        created_at=datetime(2026, 10, 8, 12, 0, tzinfo=UTC),
    )
    restored = PolicyHistoryRecord.from_event(original).to_event()
    assert restored.event_type is PolicyHistoryEventType.REGISTERED
    assert restored.actor == "operator"


def test_an_unknown_history_event_type_is_refused() -> None:
    record = PolicyHistoryRecord.from_event(
        PolicyHistoryEvent(
            policy_id=uuid4(),
            version=1,
            event_type=PolicyHistoryEventType.REGISTERED,
            actor="operator",
            created_at=datetime(2026, 10, 8, 12, 0, tzinfo=UTC),
        )
    )
    record.event_type = "unapproved-somehow"
    with pytest.raises(StoredValueError, match="policy_history.event_type"):
        record.to_event()
