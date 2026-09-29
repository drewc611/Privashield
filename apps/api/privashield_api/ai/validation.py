"""Check model output before it becomes a permanent record.

The audit ledger is append-only and hash-chained (`docs/AUDIT_LOGGING.md`), which
is the property that makes it worth trusting and also the reason nothing
unchecked may enter it. A bad entry cannot be edited out later without breaking
the chain that proves nothing was edited out.

Pydantic validates shape. Shape is not the problem. A response can satisfy
`AIThreatAnalysis` perfectly and still claim it blocked an IP, cite an event that
was never supplied, or repeat an instruction that an intruder planted in a
filename. Those are contract violations, and this module is where they stop.

A rejected response is still recorded. The refusal itself is the audit-worthy
fact: it says the model returned something outside its authority, and at what
time, which is exactly what someone investigating later needs.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from uuid import UUID

from ..schemas import AIThreatAnalysis, SecurityEvent


class ViolationKind(StrEnum):
    """Why a response was refused."""

    CLAIMED_ACTION = "claimed_action"
    FABRICATED_IDENTIFIER = "fabricated_identifier"
    ECHOED_INJECTION = "echoed_injection"
    LEAKED_DELIMITER = "leaked_delimiter"
    CONTROL_CHARACTERS = "control_characters"


#: Past-tense or present-perfect claims that something was done. ADR-0001 gives
#: the model no path to enforcement, so a claim of action is either a
#: hallucination or a sign it followed injected instructions. Both disqualify the
#: response. Phrased to catch the claim, not the proposal: "blocked the host" is
#: refused, "recommend blocking the host" is not.
ACTION_CLAIM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(i|we|the system|privashield)\s+(have\s+|has\s+|had\s+)?(already\s+)?"
        r"(blocked|quarantined|isolated|terminated|deleted|disabled|revoked|patched|"
        r"remediated|contained|enforced|applied|killed|removed)\b",
        re.I,
    ),
    re.compile(
        r"\b(has|have|was|were|been)\s+(successfully\s+)?"
        r"(blocked|quarantined|isolated|terminated|disabled|revoked|remediated|contained|"
        r"enforced|applied)\b",
        re.I,
    ),
    re.compile(
        r"\b(action|remediation|mitigation|rule|policy|firewall\s+rule)\s+"
        r"(was|has\s+been|been)\s+(taken|applied|executed|deployed|pushed|activated)\b",
        re.I,
    ),
    re.compile(
        r"\bi\s+(will|am\s+going\s+to)\s+(block|quarantine|isolate|terminate|disable)\b", re.I
    ),
)


@dataclass(frozen=True)
class Violation:
    """One reason a response was refused."""

    kind: ViolationKind
    field_path: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind.value, "field": self.field_path, "detail": self.detail}


class OutputRejected(ValueError):
    """The response violated the model's contract and must not be stored."""

    def __init__(self, violations: list[Violation]) -> None:
        self.violations = violations
        kinds = ", ".join(sorted({violation.kind.value for violation in violations}))
        super().__init__(f"model output rejected: {kinds}")

    def to_dict(self) -> dict[str, Any]:
        return {"violations": [violation.to_dict() for violation in self.violations]}


@dataclass
class ValidationContext:
    """What the response is allowed to refer to."""

    #: Identifiers that appeared in the supplied telemetry.
    known_identifiers: set[str] = field(default_factory=set)
    #: The prompt nonce, which must never appear in output.
    nonce: str | None = None
    #: Excerpts of instruction-shaped telemetry, so an echo can be spotted.
    injection_excerpts: tuple[str, ...] = ()


def context_from(
    events: list[SecurityEvent],
    *,
    nonce: str | None = None,
    injection_excerpts: tuple[str, ...] = (),
) -> ValidationContext:
    """Derive what a response may legitimately cite from the telemetry it saw."""
    known: set[str] = set()
    for event in events:
        known.add(str(event.id))
        for value in (event.src_ip, event.dst_ip, event.user_id, event.process, event.asset_id):
            if value is not None:
                known.add(str(value))
    return ValidationContext(
        known_identifiers=known, nonce=nonce, injection_excerpts=injection_excerpts
    )


_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)


def _texts(analysis: AIThreatAnalysis) -> list[tuple[str, str]]:
    parts = [("summary", analysis.summary)]
    parts += [(f"evidence[{index}]", value) for index, value in enumerate(analysis.evidence)]
    parts += [
        (f"recommended_actions[{index}]", value)
        for index, value in enumerate(analysis.recommended_actions)
    ]
    return parts


def validate_analysis(analysis: AIThreatAnalysis, context: ValidationContext) -> AIThreatAnalysis:
    """Return the analysis, or raise `OutputRejected` naming every violation.

    Every violation is collected rather than raising on the first, because an
    operator reading a refusal in the ledger needs the whole reason, not the
    first clause of it.
    """
    violations: list[Violation] = []

    for path, text in _texts(analysis):
        if any(unicodedata.category(ch) in {"Cc", "Cf"} for ch in text):
            violations.append(
                Violation(
                    kind=ViolationKind.CONTROL_CHARACTERS,
                    field_path=path,
                    detail="control or format characters can hide content from a reader",
                )
            )

        if context.nonce and context.nonce in text:
            violations.append(
                Violation(
                    kind=ViolationKind.LEAKED_DELIMITER,
                    field_path=path,
                    detail="response repeated the prompt delimiter",
                )
            )

        for pattern in ACTION_CLAIM_PATTERNS:
            match = pattern.search(text)
            if match:
                violations.append(
                    Violation(
                        kind=ViolationKind.CLAIMED_ACTION,
                        field_path=path,
                        detail=f"claims an action was taken: {match.group(0)!r}",
                    )
                )
                break

        for excerpt in context.injection_excerpts:
            if len(excerpt) >= 12 and excerpt.lower() in text.lower():
                violations.append(
                    Violation(
                        kind=ViolationKind.ECHOED_INJECTION,
                        field_path=path,
                        detail=f"repeats instruction-shaped telemetry: {excerpt[:60]!r}",
                    )
                )
                break

        # A fabricated event identifier is the one kind of grounding failure that
        # can be checked mechanically. Paraphrase is legitimate; inventing a UUID
        # that was never supplied is not.
        for candidate in _UUID_RE.findall(text):
            try:
                normalized = str(UUID(candidate))
            except ValueError:  # pragma: no cover - the regex already constrains this
                continue
            if normalized not in context.known_identifiers:
                violations.append(
                    Violation(
                        kind=ViolationKind.FABRICATED_IDENTIFIER,
                        field_path=path,
                        detail=f"cites an identifier absent from the telemetry: {normalized}",
                    )
                )

    if violations:
        raise OutputRejected(violations)
    return analysis


__all__ = [
    "ACTION_CLAIM_PATTERNS",
    "OutputRejected",
    "ValidationContext",
    "ViolationKind",
    "Violation",
    "context_from",
    "validate_analysis",
]
