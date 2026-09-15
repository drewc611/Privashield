from __future__ import annotations

from .schemas import RansomwareAssessment, RansomwareObservation, Severity


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


def assess_ransomware(observation: RansomwareObservation) -> RansomwareAssessment:
    reasons: list[str] = []
    operations_per_minute = observation.file_operations / observation.window_seconds * 60
    score = min(operations_per_minute / 1000, 1.0) * 0.35
    if operations_per_minute >= 500:
        reasons.append(f"High file-operation rate: {operations_per_minute:.0f}/min")

    rename_ratio = observation.renamed_files / max(observation.file_operations, 1)
    if observation.renamed_files >= 25 or rename_ratio >= 0.35:
        score += min(max(rename_ratio, 0.35), 1.0) * 0.2
        reasons.append("Burst of file renames detected")

    extension_ratio = observation.extension_changes / max(observation.file_operations, 1)
    if observation.extension_changes >= 20 or extension_ratio >= 0.25:
        score += min(max(extension_ratio, 0.25), 1.0) * 0.25
        reasons.append("Unusual file-extension changes detected")

    entropy_ratio = observation.high_entropy_writes / max(observation.file_operations, 1)
    if observation.high_entropy_writes >= 20 or entropy_ratio >= 0.25:
        score += min(max(entropy_ratio, 0.25), 1.0) * 0.25
        reasons.append("High-entropy write burst is consistent with encryption behavior")

    if observation.distinct_directories >= 10:
        score += 0.1
        reasons.append("Activity spans many directories")

    score = min(score, 1.0)
    severity = _severity(score)
    action = (
        "containment review recommended immediately"
        if severity in {Severity.HIGH, Severity.CRITICAL}
        else "continue monitoring"
    )
    return RansomwareAssessment(
        risk_score=score,
        severity=severity,
        reasons=reasons,
        recommended_action=action,
        enforced=False,
    )
