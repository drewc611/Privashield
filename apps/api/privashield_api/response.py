from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from .response_models import (
    ResponseAction,
    ResponseActionCreate,
    ResponseActionType,
    ResponseCapabilities,
    ResponseStatus,
)


class ResponseStore:
    def __init__(self) -> None:
        self._actions: dict[UUID, ResponseAction] = {}

    def capabilities(self) -> ResponseCapabilities:
        return ResponseCapabilities(supported_actions=list(ResponseActionType))

    def create(self, request: ResponseActionCreate) -> ResponseAction:
        action = ResponseAction(**request.model_dump())
        self._actions[action.id] = action
        return action.model_copy(deep=True)

    def list(self) -> list[ResponseAction]:
        return sorted(
            (action.model_copy(deep=True) for action in self._actions.values()),
            key=lambda action: action.created_at,
            reverse=True,
        )

    def get(self, action_id: UUID) -> ResponseAction | None:
        action = self._actions.get(action_id)
        return action.model_copy(deep=True) if action else None

    def approve(self, action_id: UUID, approved_by: str) -> ResponseAction | None:
        action = self._actions.get(action_id)
        if action is None or action.status is not ResponseStatus.PENDING:
            return None
        action.status = ResponseStatus.APPROVED
        action.approved_by = approved_by
        action.updated_at = datetime.now(UTC)
        return action.model_copy(deep=True)

    def simulate(self, action_id: UUID) -> ResponseAction | None:
        action = self._actions.get(action_id)
        if action is None or action.status is not ResponseStatus.APPROVED:
            return None
        action.status = ResponseStatus.SIMULATED
        action.execution_result = (
            f"Simulation only. No privileged change was made for {action.action_type.value} "
            f"targeting {action.target}."
        )
        action.enforced = False
        action.updated_at = datetime.now(UTC)
        return action.model_copy(deep=True)

    def cancel(self, action_id: UUID) -> ResponseAction | None:
        action = self._actions.get(action_id)
        if action is None or action.status not in {ResponseStatus.PENDING, ResponseStatus.APPROVED}:
            return None
        action.status = ResponseStatus.CANCELLED
        action.updated_at = datetime.now(UTC)
        return action.model_copy(deep=True)
