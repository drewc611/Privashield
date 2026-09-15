from fastapi import Request

from .repository import EventRepository


def get_event_repository(request: Request) -> EventRepository:
    return request.app.state.event_repository
