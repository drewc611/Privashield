from privashield_collector.normalize import normalize_suricata, normalize_zeek


def test_suricata_alert_normalization_is_privacy_minimized() -> None:
    record = {
        "timestamp": "2026-09-15T14:00:00.000000+00:00",
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "src_port": 54321,
        "dest_ip": "198.51.100.20",
        "dest_port": 443,
        "proto": "TCP",
        "flow_id": 123456,
        "app_proto": "tls",
        "alert": {
            "signature_id": 900001,
            "signature": "Suspicious outbound TLS pattern",
            "category": "Potentially Bad Traffic",
            "severity": 1,
            "action": "allowed",
        },
        "tls": {"sni": "private.example", "version": "TLS 1.3"},
    }

    event = normalize_suricata(record)

    assert event.source == "suricata"
    assert event.severity == "high"
    assert event.summary == "Suspicious outbound TLS pattern"
    assert str(event.src_ip) == "192.0.2.10"
    assert "tls" not in event.metadata
    assert event.metadata["flow_id"] == 123456
    assert event.metadata["alert"]["signature_id"] == 900001


def test_suricata_application_metadata_requires_opt_in() -> None:
    record = {
        "timestamp": "2026-09-15T14:00:00+00:00",
        "event_type": "tls",
        "tls": {"sni": "example.org", "version": "TLS 1.3"},
    }

    event = normalize_suricata(record, include_application_metadata=True)

    assert event.metadata["tls"]["sni"] == "example.org"


def test_zeek_conn_normalization_keeps_flow_features() -> None:
    record = {
        "ts": 1789480800.0,
        "uid": "C123",
        "id.orig_h": "192.0.2.25",
        "id.orig_p": 52000,
        "id.resp_h": "198.51.100.25",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 1.25,
        "orig_bytes": 2048,
        "resp_bytes": 4096,
        "conn_state": "SF",
    }

    event = normalize_zeek(record, log_type="conn")

    assert event.source == "zeek"
    assert event.event_type == "conn"
    assert event.severity == "info"
    assert event.metadata["orig_bytes"] == 2048
    assert event.metadata["resp_bytes"] == 4096


def test_zeek_application_metadata_is_hidden_by_default() -> None:
    record = {
        "ts": 1789480800.0,
        "_path": "dns",
        "id.orig_h": "192.0.2.30",
        "id.resp_h": "198.51.100.53",
        "query": "sensitive.example",
    }

    default_event = normalize_zeek(record)
    opted_in_event = normalize_zeek(record, include_application_metadata=True)

    assert "dns_query" not in default_event.metadata
    assert opted_in_event.metadata["dns_query"] == "sensitive.example"
