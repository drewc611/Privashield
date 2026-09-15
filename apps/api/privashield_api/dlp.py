from __future__ import annotations

import re
from dataclasses import dataclass

from .schemas import ClassificationMatch, DLPClassification


@dataclass(frozen=True)
class PatternDefinition:
    name: str
    pattern: re.Pattern[str]
    confidence: float
    sensitivity: str


PATTERNS = (
    PatternDefinition(
        "email",
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
        0.98,
        "confidential",
    ),
    PatternDefinition(
        "ssn",
        re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
        0.99,
        "restricted",
    ),
    PatternDefinition(
        "phone",
        re.compile(r"(?<!\d)(?:\+1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)"),
        0.82,
        "confidential",
    ),
    PatternDefinition(
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        0.99,
        "restricted",
    ),
    PatternDefinition(
        "credential",
        re.compile(
            r"(?i)\b(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*[^\s,;]{6,}"
        ),
        0.9,
        "restricted",
    ),
    PatternDefinition(
        "medical_record",
        re.compile(r"(?i)\b(?:MRN|medical record|patient id)\s*[:#-]?\s*[A-Z0-9-]{4,20}\b"),
        0.86,
        "restricted",
    ),
    PatternDefinition(
        "financial_account",
        re.compile(r"(?i)\b(?:account|routing)\s*(?:number|no\.?|#)?\s*[:=-]?\s*\d{8,17}\b"),
        0.86,
        "restricted",
    ),
)

CREDIT_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
SENSITIVITY_ORDER = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


def _luhn(candidate: str) -> bool:
    digits = [int(value) for value in re.sub(r"\D", "", candidate)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def classify_text(text: str, permission_tier: str) -> DLPClassification:
    matches: list[ClassificationMatch] = []
    match_sensitivity: list[tuple[ClassificationMatch, str]] = []
    for definition in PATTERNS:
        for match in definition.pattern.finditer(text):
            item = ClassificationMatch(
                data_type=definition.name,
                start=match.start(),
                end=match.end(),
                confidence=definition.confidence,
            )
            matches.append(item)
            match_sensitivity.append((item, definition.sensitivity))
    for match in CREDIT_CARD.finditer(text):
        if _luhn(match.group()):
            item = ClassificationMatch(
                data_type="payment_card",
                start=match.start(),
                end=match.end(),
                confidence=0.99,
            )
            matches.append(item)
            match_sensitivity.append((item, "restricted"))

    sensitivity = "public"
    for _, level in match_sensitivity:
        if SENSITIVITY_ORDER[level] > SENSITIVITY_ORDER[sensitivity]:
            sensitivity = level

    redaction_floor = {
        "public": 1,
        "internal": 3,
        "privileged": 99,
    }[permission_tier]
    spans = [
        (item.start, item.end, item.data_type)
        for item, level in match_sensitivity
        if SENSITIVITY_ORDER[level] >= redaction_floor
    ]
    redacted = text
    for start, end, data_type in sorted(spans, reverse=True):
        redacted = redacted[:start] + f"[REDACTED:{data_type.upper()}]" + redacted[end:]

    labels = sorted({item.data_type for item in matches})
    return DLPClassification(
        sensitivity=sensitivity,
        labels=labels,
        matches=sorted(matches, key=lambda item: item.start),
        redacted_text=redacted,
    )
