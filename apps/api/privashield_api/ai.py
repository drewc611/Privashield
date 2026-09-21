from __future__ import annotations

import json

import httpx

from .schemas import AIThreatAnalysis, SecurityEvent


class OllamaThreatAnalyzer:
    def __init__(self, base_url: str, model: str, enabled: bool) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.enabled = enabled

    async def analyze(
        self,
        events: list[SecurityEvent],
        question: str | None = None,
    ) -> AIThreatAnalysis:
        evidence = [
            event.model_dump(
                mode="json",
                exclude={"raw_ref"},
            )
            for event in events
        ]
        prompt = (
            "You are PrivaShield's local security analysis assistant. Analyze only the supplied "
            "telemetry. Do not claim an action was executed. Return evidence-based findings and "
            "defensive recommendations. Telemetry:\n" + json.dumps(evidence, sort_keys=True)
        )
        if question:
            prompt += f"\nAnalyst question: {question}"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": AIThreatAnalysis.model_json_schema(),
            "options": {"temperature": 0},
        }
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(f"{self.base_url}/api/generate", json=payload)
            response.raise_for_status()
        content = response.json().get("response")
        if not isinstance(content, str):
            raise ValueError("Ollama returned no structured response")
        return AIThreatAnalysis.model_validate_json(content)
