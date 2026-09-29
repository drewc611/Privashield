"""Transport for a threat-analysis model, and nothing more.

A provider moves a prompt to a model and text back. It does not parse, judge, or
decide. That split is the point: `docs/AI_MODEL_GOVERNANCE.md` and ADR-0001 put
the trust boundary between the model and the rest of the system, so the code that
talks to a model must not also be the code that decides what its answer means.
Parsing and validation live in `validation.py`, behind that boundary.

The Protocol is what makes the boundary testable. Before it, the only analyzer
was bound to Ollama's HTTP surface, so nothing about prompt construction or
output handling could be exercised without a running model.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import httpx


class ProviderError(RuntimeError):
    """The provider could not produce a response.

    Distinct from a validation failure. This means the transport failed; it does
    not mean the model said something unacceptable.
    """


@runtime_checkable
class ThreatAnalysisProvider(Protocol):
    """What the analyzer needs from a model backend."""

    #: Stable identifier for the backend, reported on the status endpoint.
    name: str
    #: Model identifier, as the backend names it.
    model: str
    #: Whether this deployment has analysis switched on.
    enabled: bool

    async def complete(self, prompt: str, *, response_schema: dict[str, object]) -> str:
        """Return the model's raw text for `prompt`.

        Raw, deliberately. A provider that parsed its own output would put
        parsing on the untrusted side of the boundary.
        """
        ...


class OllamaProvider:
    """Local Ollama backend.

    Local by design, per ADR-0003: telemetry is not sent off the appliance for
    analysis. `temperature` is fixed at 0 because a security finding that changes
    between identical requests cannot be audited.
    """

    name = "ollama-local"

    def __init__(self, base_url: str, model: str, enabled: bool, *, timeout: float = 120.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.enabled = enabled
        self.timeout = timeout

    async def complete(self, prompt: str, *, response_schema: dict[str, object]) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": response_schema,
            "options": {"temperature": 0},
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(f"{self.base_url}/api/generate", json=payload)
                response.raise_for_status()
            content = response.json().get("response")
        except httpx.HTTPError as exc:
            raise ProviderError(f"{self.name} transport failed") from exc
        if not isinstance(content, str):
            # Asking for a schema does not guarantee getting one back. A backend
            # is untrusted in the same way its output is.
            raise ProviderError(f"{self.name} returned no textual response")
        return content


class ScriptedProvider:
    """A deterministic provider that replays canned responses.

    This is a test double, and it is in the package rather than the test tree
    because the adversarial corpus harness in `evaluation/` needs it too. It is
    the only way to exercise prompt construction and output validation without a
    model, which is what makes those paths testable at all.
    """

    name = "scripted"

    def __init__(self, responses: list[str], *, model: str = "scripted", enabled: bool = True):
        if not responses:
            raise ValueError("ScriptedProvider needs at least one response")
        self.model = model
        self.enabled = enabled
        self._responses = list(responses)
        #: Every prompt this provider was handed, so a test can assert on what
        #: the analyzer actually sent rather than on what it meant to send.
        self.prompts: list[str] = []

    async def complete(self, prompt: str, *, response_schema: dict[str, object]) -> str:
        self.prompts.append(prompt)
        if len(self._responses) == 1:
            return self._responses[0]
        return self._responses.pop(0)


__all__ = ["OllamaProvider", "ProviderError", "ScriptedProvider", "ThreatAnalysisProvider"]
