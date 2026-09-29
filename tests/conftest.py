from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest


@pytest.fixture
def make_event() -> Callable[[], dict[str, Any]]:
    def build() -> dict[str, Any]:
        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "suricata",
            "event_type": "alert",
            "severity": "high",
            "src_ip": "192.0.2.10",
            "src_port": 44321,
            "dst_ip": "198.51.100.20",
            "dst_port": 443,
            "protocol": "tcp",
            "direction": "outbound",
            "summary": "Suspicious outbound TLS connection",
            "metadata": {"signature_id": 900001},
        }

    return build
