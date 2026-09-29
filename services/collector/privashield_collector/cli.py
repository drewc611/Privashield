from __future__ import annotations

import argparse
import json
import os
import socket
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_DNS, UUID, uuid5

from .client import CollectorClient
from .normalize import NormalizationError, normalize_suricata, normalize_zeek


def _records(path: Path, *, follow: bool) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        while True:
            line = handle.readline()
            if not line:
                if not follow:
                    return
                time.sleep(0.25)
                continue
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise NormalizationError(f"invalid JSON line in {path}") from exc
            if not isinstance(value, dict):
                raise NormalizationError("sensor line must contain a JSON object")
            yield value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PrivaShield sensor collector")
    parser.add_argument("--source", choices=("suricata", "zeek"), required=True)
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--zeek-log-type")
    parser.add_argument("--sensor-id", type=UUID)
    parser.add_argument("--sensor-name")
    parser.add_argument(
        "--include-application-metadata",
        action="store_true",
        help="Include DNS names, HTTP hosts, and TLS SNI in normalized metadata.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    hostname = socket.gethostname()
    sensor_id = args.sensor_id or uuid5(NAMESPACE_DNS, f"privashield:{hostname}:{args.source}")
    sensor_name = args.sensor_name or f"{args.source}-{hostname}"
    api_token = os.getenv("PRIVASHIELD_API_TOKEN") or None

    with CollectorClient(args.api_url, api_token=api_token) as client:
        client.heartbeat(
            sensor_id=sensor_id,
            name=sensor_name,
            sensor_type=args.source,
            hostname=hostname,
        )
        last_heartbeat = time.monotonic()
        for record in _records(args.file, follow=args.follow):
            if time.monotonic() - last_heartbeat >= 20:
                client.heartbeat(
                    sensor_id=sensor_id,
                    name=sensor_name,
                    sensor_type=args.source,
                    hostname=hostname,
                )
                last_heartbeat = time.monotonic()
            if args.source == "suricata":
                event = normalize_suricata(
                    record,
                    include_application_metadata=args.include_application_metadata,
                )
            else:
                event = normalize_zeek(
                    record,
                    log_type=args.zeek_log_type,
                    include_application_metadata=args.include_application_metadata,
                )
            event.sensor_id = sensor_id
            client.send(event)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
