from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .schemas import AuditEntry, AuditVerification

ZERO_HASH = "0" * 64


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


class AuditLedger:
    def __init__(self, path: str | None = None) -> None:
        self._path = Path(path) if path else None
        self._entries: list[AuditEntry] = []
        self._lock = asyncio.Lock()
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if self._path.exists():
                for line in self._path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        self._entries.append(AuditEntry.model_validate_json(line))

    async def append(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: Any,
    ) -> AuditEntry:
        async with self._lock:
            sequence = len(self._entries) + 1
            timestamp = datetime.now(UTC)
            previous_hash = self._entries[-1].entry_hash if self._entries else ZERO_HASH
            payload_hash = _digest(payload)
            material: dict[str, Any] = {
                "sequence": sequence,
                "timestamp": timestamp.isoformat(),
                "actor": actor,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "payload_hash": payload_hash,
                "previous_hash": previous_hash,
            }
            entry = AuditEntry(
                **material,
                entry_hash=_digest(material),
            )
            self._entries.append(entry)
            if self._path is not None:
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(entry.model_dump_json() + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            return entry

    def list(self, limit: int = 200) -> list[AuditEntry]:
        return self._entries[-limit:]

    def verify(self) -> AuditVerification:
        previous_hash = ZERO_HASH
        for entry in self._entries:
            material = {
                "sequence": entry.sequence,
                "timestamp": entry.timestamp.isoformat(),
                "actor": entry.actor,
                "action": entry.action,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "payload_hash": entry.payload_hash,
                "previous_hash": entry.previous_hash,
            }
            if entry.previous_hash != previous_hash or entry.entry_hash != _digest(material):
                return AuditVerification(
                    valid=False,
                    entries=len(self._entries),
                    first_invalid_sequence=entry.sequence,
                )
            previous_hash = entry.entry_hash
        return AuditVerification(valid=True, entries=len(self._entries))
