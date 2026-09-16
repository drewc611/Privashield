from __future__ import annotations

import hashlib
import math
import os
import socket
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from uuid import NAMESPACE_DNS, uuid5

import httpx
from watchfiles import Change, watch


@dataclass(frozen=True)
class FileSample:
    filename: str
    extension: str
    size_bytes: int
    entropy: float
    path_hash: str


def file_entropy(path: Path, sample_bytes: int = 65536) -> float:
    try:
        with path.open("rb") as handle:
            data = handle.read(sample_bytes)
    except (OSError, PermissionError):
        return 0.0
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def sample_file(path: Path) -> FileSample | None:
    try:
        stat = path.stat()
    except (OSError, FileNotFoundError, PermissionError):
        return None
    if not path.is_file():
        return None
    return FileSample(
        filename=path.name,
        extension=path.suffix.lower(),
        size_bytes=stat.st_size,
        entropy=file_entropy(path),
        path_hash=hashlib.sha256(str(path).encode()).hexdigest(),
    )


def summarize_changes(changes: set[tuple[Change, str]]) -> dict[str, int]:
    added = [Path(path) for change, path in changes if change is Change.added]
    deleted = [Path(path) for change, path in changes if change is Change.deleted]
    modified = [Path(path) for change, path in changes if change is Change.modified]
    likely_renames = min(len(added), len(deleted))
    deleted_suffixes = Counter(path.suffix.lower() for path in deleted)
    added_suffixes = Counter(path.suffix.lower() for path in added)
    same_suffix_pairs = sum((deleted_suffixes & added_suffixes).values())
    extension_changes = max(likely_renames - same_suffix_pairs, 0)
    return {
        "file_operations": len(changes),
        "renamed_files": likely_renames,
        "extension_changes": extension_changes,
        "modified_files": len(modified),
    }


class FileMonitor:
    def __init__(self, api_url: str, watch_path: Path, *, api_token: str | None = None) -> None:
        self.api_url = api_url.rstrip("/")
        self.watch_path = watch_path
        self.hostname = socket.gethostname()
        self.sensor_id = uuid5(NAMESPACE_DNS, f"privashield:{self.hostname}:file-monitor")
        headers = {"Authorization": f"Bearer {api_token}"} if api_token else None
        self.client = httpx.Client(timeout=15, headers=headers)
        self.last_heartbeat = 0.0

    def heartbeat(self) -> None:
        self.client.post(
            f"{self.api_url}/api/v1/sensors/heartbeat",
            json={
                "sensor_id": str(self.sensor_id),
                "name": f"file-monitor-{self.hostname}",
                "sensor_type": "file-monitor",
                "hostname": self.hostname,
                "interface": str(self.watch_path),
                "capabilities": ["filesystem-events", "entropy-sampling", "ransomware-behavior"],
            },
        ).raise_for_status()
        self.last_heartbeat = time.monotonic()

    def _emit_event(self, severity: str, summary: str, metadata: dict[str, object]) -> None:
        self.client.post(
            f"{self.api_url}/api/v1/events/ingest",
            json={
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "source": "host",
                "event_type": "filesystem_detection",
                "severity": severity,
                "sensor_id": str(self.sensor_id),
                "summary": summary,
                "metadata": metadata,
            },
        ).raise_for_status()

    def _assess_file(self, sample: FileSample) -> None:
        response = self.client.post(
            f"{self.api_url}/api/v1/malware/evaluate",
            json={
                "filename": sample.filename,
                "size_bytes": sample.size_bytes,
                "entropy": sample.entropy,
                "known_signature_match": False,
            },
        )
        response.raise_for_status()
        result = response.json()
        if result["severity"] in {"medium", "high", "critical"}:
            self._emit_event(
                result["severity"],
                "File risk heuristic triggered on monitored filesystem",
                {
                    "path_hash": sample.path_hash,
                    "extension": sample.extension,
                    "risk_score": result["risk_score"],
                    "indicators": result["indicators"],
                },
            )

    def _assess_batch(self, changes: set[tuple[Change, str]], elapsed: float) -> None:
        summary = summarize_changes(changes)
        samples: list[FileSample] = []
        directories: set[str] = set()
        for change, value in changes:
            path = Path(value)
            directories.add(hashlib.sha256(str(path.parent).encode()).hexdigest())
            if change in {Change.added, Change.modified}:
                sample = sample_file(path)
                if sample is not None:
                    samples.append(sample)
                    self._assess_file(sample)
        high_entropy = sum(1 for sample in samples if sample.entropy >= 7.5)
        response = self.client.post(
            f"{self.api_url}/api/v1/ransomware/evaluate",
            json={
                "window_seconds": max(elapsed, 0.1),
                "file_operations": summary["file_operations"],
                "renamed_files": summary["renamed_files"],
                "extension_changes": summary["extension_changes"],
                "high_entropy_writes": high_entropy,
                "distinct_directories": len(directories),
            },
        )
        response.raise_for_status()
        result = response.json()
        if result["severity"] in {"high", "critical"}:
            self._emit_event(
                result["severity"],
                "Ransomware-like filesystem behavior detected",
                {
                    "risk_score": result["risk_score"],
                    "reasons": result["reasons"],
                    "window_seconds": max(elapsed, 0.1),
                    "operation_count": summary["file_operations"],
                },
            )

    def run(self) -> None:
        self.heartbeat()
        previous = time.monotonic()
        for changes in watch(self.watch_path, recursive=True, raise_interrupt=False):
            now = time.monotonic()
            if now - self.last_heartbeat >= 20:
                self.heartbeat()
            self._assess_batch(changes, now - previous)
            previous = now


def main() -> int:
    api_url = os.environ.get("PRIVASHIELD_API_URL", "http://api:8000")
    api_token = os.environ.get("PRIVASHIELD_API_TOKEN") or None
    watch_path = Path(os.environ.get("PRIVASHIELD_WATCH_PATH", "/watch"))
    if not watch_path.exists() or not watch_path.is_dir():
        raise SystemExit(f"Monitored path is not a directory: {watch_path}")
    FileMonitor(api_url, watch_path, api_token=api_token).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
