from __future__ import annotations

import math
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

from .schemas import AnomalyAssessment, IdentityObservation, Severity


def _severity(score: float) -> Severity:
    if score >= 0.85:
        return Severity.CRITICAL
    if score >= 0.65:
        return Severity.HIGH
    if score >= 0.4:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    value = (
        math.sin(delta_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    )
    return radius * 2 * math.atan2(math.sqrt(value), math.sqrt(1 - value))


class AnomalyEngine:
    def __init__(self) -> None:
        self._last_login: dict[str, IdentityObservation] = {}
        self._downloads: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)

    def evaluate(self, observation: IdentityObservation) -> AnomalyAssessment:
        reasons: list[str] = []
        score = 0.0
        timestamp = observation.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)

        if observation.event_type == "login":
            previous = self._last_login.get(observation.user_id)
            if (
                previous
                and previous.latitude is not None
                and previous.longitude is not None
                and observation.latitude is not None
                and observation.longitude is not None
            ):
                previous_time = previous.timestamp
                if previous_time.tzinfo is None:
                    previous_time = previous_time.replace(tzinfo=UTC)
                hours = max((timestamp - previous_time).total_seconds() / 3600, 1 / 3600)
                distance = _distance_km(
                    previous.latitude,
                    previous.longitude,
                    observation.latitude,
                    observation.longitude,
                )
                speed = distance / hours
                if distance >= 500 and speed >= 1000:
                    score += 0.75
                    reasons.append(
                        f"Impossible travel: {distance:.0f} km in {hours:.2f} h ({speed:.0f} km/h)"
                    )
            self._last_login[observation.user_id] = observation

        if observation.downloaded_bytes:
            history = self._downloads[observation.user_id]
            history.append((timestamp, observation.downloaded_bytes))
            cutoff = timestamp - timedelta(minutes=10)
            while history and history[0][0] < cutoff:
                history.popleft()
            total = sum(value for _, value in history)
            if observation.downloaded_bytes >= 500 * 1024 * 1024:
                score += 0.45
                reasons.append("Single download exceeded 500 MiB")
            if total >= 1024 * 1024 * 1024:
                score += 0.45
                reasons.append("Ten-minute download volume exceeded 1 GiB")

        score = min(score, 1.0)
        return AnomalyAssessment(
            user_id=observation.user_id,
            risk_score=score,
            severity=_severity(score),
            reasons=reasons,
        )
