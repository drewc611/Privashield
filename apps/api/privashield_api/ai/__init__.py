"""Local AI threat analysis, under the authority boundary ADR-0001 draws.

Four pieces, split along the trust boundaries rather than by convenience:

- `provider` moves a prompt to a model and text back. Transport only.
- `prompt` builds prompts that treat telemetry as hostile input.
- `validation` refuses model output that breaks its contract, before that output
  can reach the append-only audit ledger.
- `analyzer` runs the pipeline in the one order that keeps each boundary crossed
  in the safe direction.

`docs/AI_MODEL_GOVERNANCE.md` describes the intent. This package is where it is
enforced in code.
"""

from .analyzer import AnalysisOutcome, ThreatAnalyzer
from .prompt import InjectionFinding, Prompt, build_prompt, scan_for_injection
from .provider import OllamaProvider, ProviderError, ScriptedProvider, ThreatAnalysisProvider
from .validation import (
    OutputRejected,
    ValidationContext,
    Violation,
    ViolationKind,
    context_from,
    validate_analysis,
)

__all__ = [
    "AnalysisOutcome",
    "InjectionFinding",
    "OllamaProvider",
    "OutputRejected",
    "Prompt",
    "ProviderError",
    "ScriptedProvider",
    "ThreatAnalysisProvider",
    "ThreatAnalyzer",
    "ValidationContext",
    "Violation",
    "ViolationKind",
    "build_prompt",
    "context_from",
    "scan_for_injection",
    "validate_analysis",
]
