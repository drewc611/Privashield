from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from ..ai import OutputRejected, ProviderError, ThreatAnalyzer
from ..audit import AuditLedger
from ..dependencies import get_ai_analyzer, get_audit_ledger, get_event_repository
from ..repository import EventRepository
from ..schemas import AIAnalysisRequest, AIStatus, AIThreatAnalysis

router = APIRouter(prefix="/ai", tags=["ai"])
RepositoryDependency = Annotated[EventRepository, Depends(get_event_repository)]
AnalyzerDependency = Annotated[ThreatAnalyzer, Depends(get_ai_analyzer)]
AuditDependency = Annotated[AuditLedger, Depends(get_audit_ledger)]


@router.get("/status", response_model=AIStatus)
async def ai_status(analyzer: AnalyzerDependency) -> AIStatus:
    return AIStatus(enabled=analyzer.enabled, provider=analyzer.name, model=analyzer.model)


@router.post("/analyze", response_model=AIThreatAnalysis)
async def analyze(
    request: AIAnalysisRequest,
    repository: RepositoryDependency,
    analyzer: AnalyzerDependency,
    audit: AuditDependency,
) -> AIThreatAnalysis:
    if not analyzer.enabled:
        raise HTTPException(status_code=503, detail="local AI analysis is disabled")
    events = []
    for event_id in request.event_ids:
        event = await repository.get(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail=f"event not found: {event_id}")
        events.append(event)

    resource_id = ",".join(str(value) for value in request.event_ids)
    try:
        outcome = await analyzer.analyze(events, request.question)
    except OutputRejected as exc:
        # The refusal is the audit-worthy fact. Recording only successes would
        # leave no trace that the model returned something outside its authority,
        # which is exactly what an investigation later needs to see.
        await audit.append(
            actor="local-ai",
            action="ai.analysis.rejected",
            resource_type="security_event_set",
            resource_id=resource_id,
            payload=exc.to_dict(),
        )
        raise HTTPException(
            status_code=502, detail="local AI analysis returned output that failed validation"
        ) from exc
    except ProviderError as exc:
        raise HTTPException(status_code=502, detail="local AI analysis failed") from exc

    await audit.append(
        actor="local-ai",
        action="ai.analysis.completed",
        resource_type="security_event_set",
        resource_id=resource_id,
        payload=outcome.to_dict(),
    )
    return outcome.analysis
