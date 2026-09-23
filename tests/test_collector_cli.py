from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_DNS, UUID, uuid5

import pytest

from privashield_api.schemas import SecurityEvent
from privashield_collector import cli
from privashield_collector.normalize import NormalizationError

SURICATA_ALERT: dict[str, Any] = {
    "timestamp": "2026-09-15T14:00:00.000000+00:00",
    "event_type": "alert",
    "src_ip": "192.0.2.10",
    "src_port": 54321,
    "dest_ip": "198.51.100.20",
    "dest_port": 443,
    "proto": "TCP",
    "app_proto": "tls",
    "alert": {
        "signature_id": 900001,
        "signature": "Suspicious outbound TLS pattern",
        "category": "Potentially Bad Traffic",
        "severity": 1,
    },
    "tls": {"sni": "private.example", "version": "TLS 1.3"},
}

ZEEK_CONN: dict[str, Any] = {
    "ts": 1789480800.0,
    "uid": "CabCdE1234",
    "id.orig_h": "192.0.2.10",
    "id.orig_p": 54321,
    "id.resp_h": "198.51.100.20",
    "id.resp_p": 443,
    "proto": "tcp",
}


class RecordingClient:
    """Stands in for CollectorClient and records what the CLI would send."""

    instances: list[RecordingClient] = []

    def __init__(self, api_url: str, *, api_token: str | None = None) -> None:
        self.api_url = api_url
        self.api_token = api_token
        self.heartbeats: list[dict[str, Any]] = []
        self.events: list[SecurityEvent] = []
        self.closed = False
        RecordingClient.instances.append(self)

    def __enter__(self) -> RecordingClient:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.closed = True

    def heartbeat(self, **kwargs: Any) -> None:
        self.heartbeats.append(kwargs)

    def send(self, event: SecurityEvent) -> None:
        self.events.append(event)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch) -> None:
    RecordingClient.instances = []
    monkeypatch.setattr(cli, "CollectorClient", RecordingClient)
    monkeypatch.setattr(cli.socket, "gethostname", lambda: "edge-01")
    monkeypatch.delenv("PRIVASHIELD_API_TOKEN", raising=False)


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    return path


def run(argv: list[str]) -> int:
    return cli.main(argv)


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


def test_source_and_file_are_required() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


def test_source_is_restricted_to_known_sensors() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--source", "netflow", "--file", "x.json"])


def test_parser_defaults() -> None:
    args = cli.build_parser().parse_args(["--source", "zeek", "--file", "conn.log"])
    assert args.api_url == "http://127.0.0.1:8000"
    assert args.follow is False
    assert args.include_application_metadata is False
    assert args.sensor_id is None
    assert args.sensor_name is None


# --------------------------------------------------------------------------
# Record iteration
# --------------------------------------------------------------------------


def test_records_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "eve.json"
    path.write_text('{"a": 1}\n\n   \n{"b": 2}\n', encoding="utf-8")
    assert list(cli._records(path, follow=False)) == [{"a": 1}, {"b": 2}]


def test_records_rejects_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "eve.json"
    path.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(NormalizationError, match="invalid JSON line"):
        list(cli._records(path, follow=False))


def test_records_rejects_non_object_lines(tmp_path: Path) -> None:
    path = tmp_path / "eve.json"
    path.write_text("[1, 2, 3]\n", encoding="utf-8")
    with pytest.raises(NormalizationError, match="must contain a JSON object"):
        list(cli._records(path, follow=False))


def test_records_stops_at_eof_without_follow(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT])
    assert len(list(cli._records(path, follow=False))) == 1


# --------------------------------------------------------------------------
# main()
# --------------------------------------------------------------------------


def test_forwards_suricata_events(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT, SURICATA_ALERT])

    assert run(["--source", "suricata", "--file", str(path)]) == 0

    client = RecordingClient.instances[0]
    assert len(client.events) == 2
    assert client.events[0].source == "suricata"
    assert client.events[0].severity == "high"
    assert client.closed is True


def test_forwards_zeek_events(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "conn.log", [ZEEK_CONN])

    assert run(["--source", "zeek", "--file", str(path), "--zeek-log-type", "conn"]) == 0

    client = RecordingClient.instances[0]
    assert len(client.events) == 1
    assert client.events[0].source == "zeek"


def test_sensor_id_is_derived_deterministically_from_host_and_source(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT])
    expected = uuid5(NAMESPACE_DNS, "privashield:edge-01:suricata")

    run(["--source", "suricata", "--file", str(path)])

    client = RecordingClient.instances[0]
    assert client.heartbeats[0]["sensor_id"] == expected
    assert client.heartbeats[0]["name"] == "suricata-edge-01"
    assert client.events[0].sensor_id == expected


def test_explicit_sensor_identity_overrides_the_derived_one(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT])
    sensor_id = UUID("99999999-8888-7777-6666-555555555555")

    run(
        [
            "--source",
            "suricata",
            "--file",
            str(path),
            "--sensor-id",
            str(sensor_id),
            "--sensor-name",
            "perimeter-ids",
        ]
    )

    client = RecordingClient.instances[0]
    assert client.heartbeats[0]["sensor_id"] == sensor_id
    assert client.heartbeats[0]["name"] == "perimeter-ids"
    assert client.events[0].sensor_id == sensor_id


def test_heartbeat_is_sent_before_any_event(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT])

    run(["--source", "suricata", "--file", str(path)])

    client = RecordingClient.instances[0]
    assert len(client.heartbeats) == 1
    assert client.heartbeats[0]["sensor_type"] == "suricata"
    assert client.heartbeats[0]["hostname"] == "edge-01"


def test_heartbeat_repeats_once_the_interval_elapses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT] * 3)
    # Start at 0, then jump past the 20s heartbeat interval before each event.
    ticks = iter([0.0, 25.0, 25.0, 50.0, 50.0, 75.0, 75.0])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(ticks))

    run(["--source", "suricata", "--file", str(path)])

    client = RecordingClient.instances[0]
    assert len(client.events) == 3
    assert len(client.heartbeats) == 4  # one at startup, one per elapsed interval


def test_heartbeat_does_not_repeat_within_the_interval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT] * 3)
    monkeypatch.setattr(cli.time, "monotonic", lambda: 1.0)

    run(["--source", "suricata", "--file", str(path)])

    client = RecordingClient.instances[0]
    assert len(client.heartbeats) == 1


def test_api_token_is_read_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT])
    monkeypatch.setenv("PRIVASHIELD_API_TOKEN", "collector-token")

    run(["--source", "suricata", "--file", str(path)])

    assert RecordingClient.instances[0].api_token == "collector-token"


def test_empty_api_token_is_treated_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT])
    monkeypatch.setenv("PRIVASHIELD_API_TOKEN", "")

    run(["--source", "suricata", "--file", str(path)])

    assert RecordingClient.instances[0].api_token is None


def test_application_metadata_is_withheld_by_default(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT])

    run(["--source", "suricata", "--file", str(path)])

    metadata = RecordingClient.instances[0].events[0].metadata
    assert "private.example" not in json.dumps(metadata)


def test_application_metadata_is_included_when_requested(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT])

    run(
        [
            "--source",
            "suricata",
            "--file",
            str(path),
            "--include-application-metadata",
        ]
    )

    metadata = RecordingClient.instances[0].events[0].metadata
    assert "private.example" in json.dumps(metadata)


def test_api_url_is_passed_through_to_the_client(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "eve.json", [SURICATA_ALERT])

    run(["--source", "suricata", "--file", str(path), "--api-url", "http://api.internal:9000"])

    assert RecordingClient.instances[0].api_url == "http://api.internal:9000"


def test_malformed_input_aborts_the_run(tmp_path: Path) -> None:
    path = tmp_path / "eve.json"
    path.write_text(json.dumps(SURICATA_ALERT) + "\n{broken}\n", encoding="utf-8")

    with pytest.raises(NormalizationError):
        run(["--source", "suricata", "--file", str(path)])

    client = RecordingClient.instances[0]
    assert len(client.events) == 1  # the valid line was forwarded before the failure
    assert client.closed is True  # the context manager still tore the client down
