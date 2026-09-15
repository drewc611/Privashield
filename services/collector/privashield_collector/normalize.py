from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from privashield_api.schemas import EventSource, SecurityEvent, Severity


class NormalizationError(ValueError):
    """Raised when sensor telemetry cannot be normalized safely."""


def _timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise NormalizationError("invalid event timestamp") from exc
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed
    raise NormalizationError("event timestamp is required")


def _suricata_severity(alert: dict[str, Any] | None) -> Severity:
    if not alert:
        return Severity.INFO
    try:
        level = int(alert.get("severity", 4))
    except (TypeError, ValueError):
        return Severity.INFO
    return {
        1: Severity.HIGH,
        2: Severity.MEDIUM,
        3: Severity.LOW,
    }.get(level, Severity.INFO)


def _suricata_metadata(
    record: dict[str, Any], *, include_application_metadata: bool
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    field_map = {
        "flow_id": "flow_id",
        "community_id": "community_id",
        "app_proto": "app_proto",
        "in_iface": "interface",
    }
    for source_key, target_key in field_map.items():
        value = record.get(source_key)
        if value is not None:
            metadata[target_key] = value

    alert = record.get("alert")
    if isinstance(alert, dict):
        metadata["alert"] = {
            key: alert[key]
            for key in ("signature_id", "rev", "category", "action")
            if key in alert
        }

    if include_application_metadata:
        dns = record.get("dns")
        if isinstance(dns, dict):
            metadata["dns"] = {
                key: dns[key]
                for key in ("rrname", "rrtype", "rcode")
                if key in dns
            }
        http = record.get("http")
        if isinstance(http, dict):
            metadata["http"] = {
                key: http[key]
                for key in ("hostname", "http_method", "status")
                if key in http
            }
        tls = record.get("tls")
        if isinstance(tls, dict):
            metadata["tls"] = {
                key: tls[key]
                for key in ("sni", "version", "ja3", "ja4")
                if key in tls
            }

    return metadata


def normalize_suricata(
    record: dict[str, Any], *, include_application_metadata: bool = False
) -> SecurityEvent:
    event_type = str(record.get("event_type") or "unknown")
    alert = record.get("alert") if isinstance(record.get("alert"), dict) else None
    summary = (
        str(alert.get("signature"))
        if alert and alert.get("signature")
        else f"Suricata {event_type} event"
    )

    return SecurityEvent(
        timestamp=_timestamp(record.get("timestamp")),
        source=EventSource.SURICATA,
        event_type=event_type,
        severity=_suricata_severity(alert),
        src_ip=record.get("src_ip"),
        src_port=record.get("src_port"),
        dst_ip=record.get("dest_ip"),
        dst_port=record.get("dest_port"),
        protocol=str(record.get("proto")).lower() if record.get("proto") else None,
        summary=summary,
        metadata=_suricata_metadata(
            record,
            include_application_metadata=include_application_metadata,
        ),
    )


def _zeek_metadata(
    record: dict[str, Any], *, include_application_metadata: bool
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key in (
        "uid",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
        "conn_state",
        "local_orig",
        "local_resp",
    ):
        if key in record:
            metadata[key] = record[key]

    if include_application_metadata:
        application_fields = {
            "query": "dns_query",
            "host": "http_host",
            "server_name": "tls_sni",
        }
        for source_key, target_key in application_fields.items():
            value = record.get(source_key)
            if value is not None:
                metadata[target_key] = value

    return metadata


def normalize_zeek(
    record: dict[str, Any],
    *,
    log_type: str | None = None,
    include_application_metadata: bool = False,
) -> SecurityEvent:
    resolved_type = str(log_type or record.get("_path") or "event")
    timestamp = record.get("ts", record.get("timestamp"))
    orig_h = record.get("id.orig_h")
    orig_p = record.get("id.orig_p")
    resp_h = record.get("id.resp_h")
    resp_p = record.get("id.resp_p")

    return SecurityEvent(
        timestamp=_timestamp(timestamp),
        source=EventSource.ZEEK,
        event_type=resolved_type,
        severity=Severity.INFO,
        src_ip=orig_h,
        src_port=orig_p,
        dst_ip=resp_h,
        dst_port=resp_p,
        protocol=str(record.get("proto")).lower() if record.get("proto") else None,
        summary=f"Zeek {resolved_type} event",
        metadata=_zeek_metadata(
            record,
            include_application_metadata=include_application_metadata,
        ),
    )
