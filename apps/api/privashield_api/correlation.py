from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, Field

from .schemas import EventSource, SecurityEvent, Severity


class CorrelationRequest(BaseModel):
    event_ids: list[UUID] = Field(min_length=2, max_length=100)
    max_time_gap_seconds: int = Field(default=900, ge=1, le=86400)


class SharedIndicator(BaseModel):
    indicator_type: Literal["correlation_id", "asset_id", "user_id", "ip"]
    value: str


class IncidentCorrelation(BaseModel):
    correlation_id: UUID
    first_seen: datetime
    last_seen: datetime
    severity: Severity
    score: float = Field(ge=0.0, le=1.0)
    event_ids: list[UUID]
    sources: list[EventSource]
    shared_indicators: list[SharedIndicator]
    reasons: list[str]
    event_count: int
    source_count: int
    enforced: bool = False


class CorrelationResult(BaseModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    evaluated_events: int
    incidents: list[IncidentCorrelation]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _endpoint_ips(event: SecurityEvent) -> set[str]:
    values: set[str] = set()
    if event.src_ip is not None:
        values.add(str(event.src_ip))
    if event.dst_ip is not None:
        values.add(str(event.dst_ip))
    return values


def _pair_indicators(left: SecurityEvent, right: SecurityEvent) -> list[SharedIndicator]:
    indicators: list[SharedIndicator] = []

    if left.correlation_id is not None and left.correlation_id == right.correlation_id:
        indicators.append(
            SharedIndicator(indicator_type="correlation_id", value=str(left.correlation_id))
        )
    if left.asset_id is not None and left.asset_id == right.asset_id:
        indicators.append(SharedIndicator(indicator_type="asset_id", value=str(left.asset_id)))
    if left.user_id and left.user_id == right.user_id:
        indicators.append(SharedIndicator(indicator_type="user_id", value=left.user_id))

    for ip_value in sorted(_endpoint_ips(left) & _endpoint_ips(right)):
        indicators.append(SharedIndicator(indicator_type="ip", value=ip_value))

    return indicators


def _component_indicators(events: list[SecurityEvent]) -> list[SharedIndicator]:
    values: dict[str, Counter[str]] = defaultdict(Counter)
    for event in events:
        if event.correlation_id is not None:
            values["correlation_id"][str(event.correlation_id)] += 1
        if event.asset_id is not None:
            values["asset_id"][str(event.asset_id)] += 1
        if event.user_id:
            values["user_id"][event.user_id] += 1
        for ip_value in _endpoint_ips(event):
            values["ip"][ip_value] += 1

    indicators: list[SharedIndicator] = []
    for indicator_type in ("correlation_id", "asset_id", "user_id", "ip"):
        for value, count in sorted(values[indicator_type].items()):
            if count >= 2:
                indicators.append(
                    SharedIndicator(indicator_type=indicator_type, value=value)  # type: ignore[arg-type]
                )
    return indicators


def _incident_score(
    events: list[SecurityEvent], indicators: list[SharedIndicator], source_count: int
) -> float:
    indicator_types = {item.indicator_type for item in indicators}
    score = 0.45
    if "correlation_id" in indicator_types:
        score += 0.20
    if "asset_id" in indicator_types:
        score += 0.20
    if "user_id" in indicator_types:
        score += 0.15
    if "ip" in indicator_types:
        score += 0.10
    if source_count > 2:
        score += min(0.10, (source_count - 2) * 0.05)
    if any(event.severity in {Severity.HIGH, Severity.CRITICAL} for event in events):
        score += 0.05
    return round(min(score, 1.0), 3)


def _incident_reasons(
    events: list[SecurityEvent], indicators: list[SharedIndicator], source_count: int
) -> list[str]:
    reasons = [
        f"{len(events)} related events observed across {source_count} distinct sources"
    ]
    type_labels = {
        "correlation_id": "existing correlation identifier",
        "asset_id": "asset identifier",
        "user_id": "user identifier",
        "ip": "network endpoint",
    }
    for indicator_type in ("correlation_id", "asset_id", "user_id", "ip"):
        count = sum(1 for item in indicators if item.indicator_type == indicator_type)
        if count:
            reasons.append(f"shared {type_labels[indicator_type]} evidence ({count})")
    if any(event.severity in {Severity.HIGH, Severity.CRITICAL} for event in events):
        reasons.append("cluster contains high or critical severity telemetry")
    return reasons


def correlate_events(
    events: list[SecurityEvent], *, max_time_gap_seconds: int = 900
) -> CorrelationResult:
    """Build deterministic cross-source incident candidates from observable event evidence.

    Events are graph nodes. Two nodes are linked only when they occur within the configured
    time gap and share at least one concrete identity indicator. Connected components become
    incident candidates only when they contain at least two events from at least two distinct
    sources. No model output or enforcement action participates in this decision.
    """

    if max_time_gap_seconds < 1 or max_time_gap_seconds > 86400:
        raise ValueError("max_time_gap_seconds must be between 1 and 86400")

    unique_events = {event.id: event for event in events}
    ordered = sorted(unique_events.values(), key=lambda event: (event.timestamp, str(event.id)))
    adjacency: dict[UUID, set[UUID]] = {event.id: set() for event in ordered}

    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            gap_seconds = abs((right.timestamp - left.timestamp).total_seconds())
            if gap_seconds > max_time_gap_seconds:
                if right.timestamp >= left.timestamp:
                    break
                continue
            if not _pair_indicators(left, right):
                continue
            adjacency[left.id].add(right.id)
            adjacency[right.id].add(left.id)

    by_id = {event.id: event for event in ordered}
    visited: set[UUID] = set()
    incidents: list[IncidentCorrelation] = []

    for event in ordered:
        if event.id in visited:
            continue
        stack = [event.id]
        component_ids: list[UUID] = []
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            component_ids.append(current)
            stack.extend(sorted(adjacency[current] - visited, key=str))

        if len(component_ids) < 2:
            continue
        component = sorted(
            (by_id[event_id] for event_id in component_ids),
            key=lambda item: (item.timestamp, str(item.id)),
        )
        sources = sorted({item.source for item in component}, key=lambda item: item.value)
        if len(sources) < 2:
            continue

        indicators = _component_indicators(component)
        if not indicators:
            continue

        stable_ids = ",".join(sorted(str(item.id) for item in component))
        correlation_id = uuid5(NAMESPACE_URL, f"privashield:incident:{stable_ids}")
        severity = max((item.severity for item in component), key=_SEVERITY_RANK.__getitem__)
        incidents.append(
            IncidentCorrelation(
                correlation_id=correlation_id,
                first_seen=component[0].timestamp,
                last_seen=component[-1].timestamp,
                severity=severity,
                score=_incident_score(component, indicators, len(sources)),
                event_ids=[item.id for item in component],
                sources=sources,
                shared_indicators=indicators,
                reasons=_incident_reasons(component, indicators, len(sources)),
                event_count=len(component),
                source_count=len(sources),
            )
        )

    incidents.sort(key=lambda item: (item.score, item.last_seen), reverse=True)
    return CorrelationResult(evaluated_events=len(ordered), incidents=incidents)
