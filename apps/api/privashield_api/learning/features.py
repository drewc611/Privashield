"""Deterministic feature extraction for the adaptive detection layer.

Two properties matter more than predictive power here.

Privacy: PrivaShield is local-first and minimizes retained data, so no raw
identifier ever reaches a model weight. IP addresses, user identifiers, process
names and summary tokens are folded into fixed hash buckets. A bucket index
cannot be reversed into the value that produced it, and many values share a
bucket, so weights cannot be read back as a record of who did what.

Boundedness: the model is meant to keep learning indefinitely. Hashing into a
fixed dimension means the parameter count is decided at configuration time
rather than growing with every new host, user or signature the sensors observe.

Extraction is pure and deterministic: the same event always produces the same
features, on any machine and in any process. The detection benchmark depends on
that, and so does anyone trying to reproduce a scoring decision after the fact.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping

from ..schemas import SecurityEvent, Severity

# Fixed-width hashing space for high-cardinality values. Raising this reduces
# collisions and increases the parameter count; it is a deployment trade-off,
# not a tuning knob to change casually, because changing it invalidates any
# model state trained under the previous value.
HASH_DIMENSION = 512

# Summary text is attacker-influenced (signature names, filenames, URLs all
# reach it). Cap how many tokens one event may contribute so a long crafted
# summary cannot dominate the feature vector.
MAX_SUMMARY_TOKENS = 24

SEVERITY_ORDINAL: Mapping[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.0,
}

# Ports commonly abused for remote access, lateral movement and exfiltration.
# Named rather than hashed, because these carry meaning worth keeping legible
# in the weights when an analyst asks why a score moved.
NOTABLE_PORTS: Mapping[int, str] = {
    22: "ssh",
    23: "telnet",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    4444: "metasploit_default",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    9001: "tor_orport",
    27017: "mongodb",
}


def _bucket(namespace: str, value: str, dimension: int = HASH_DIMENSION) -> str:
    """Fold a high-cardinality value into a stable, non-reversible bucket.

    blake2b with a fixed digest size is used rather than the built-in hash()
    because Python randomizes string hashing per process. A feature name has to
    mean the same thing across restarts or persisted weights become nonsense.
    """
    digest = hashlib.blake2b(
        f"{namespace}\x00{value}".encode(),
        digest_size=8,
    ).digest()
    return f"{namespace}#{int.from_bytes(digest, 'big') % dimension}"


def _tokenize_summary(summary: str) -> list[str]:
    """Split a summary into lowercase alphanumeric tokens, bounded in count."""
    tokens: list[str] = []
    current: list[str] = []
    for character in summary.lower():
        if character.isalnum():
            current.append(character)
            continue
        if current:
            tokens.append("".join(current))
            current = []
            if len(tokens) >= MAX_SUMMARY_TOKENS:
                return tokens
    if current and len(tokens) < MAX_SUMMARY_TOKENS:
        tokens.append("".join(current))
    return tokens


def _port_features(port: int | None, side: str) -> dict[str, float]:
    if port is None:
        return {f"{side}_port_absent": 1.0}
    features = {f"{side}_port_present": 1.0}
    if port in NOTABLE_PORTS:
        features[f"{side}_port_{NOTABLE_PORTS[port]}"] = 1.0
    if port < 1024:
        features[f"{side}_port_wellknown"] = 1.0
    elif port < 49152:
        features[f"{side}_port_registered"] = 1.0
    else:
        features[f"{side}_port_ephemeral"] = 1.0
    return features


def extract_features(event: SecurityEvent) -> dict[str, float]:
    """Turn a security event into a sparse, bounded, privacy-preserving vector.

    Returns a mapping of feature name to value. Names are stable across
    processes and releases; values are already scaled to roughly [0, 1] so no
    separate normalization pass is needed before an online update.
    """
    features: dict[str, float] = {"bias": 1.0}

    # Low-cardinality enums are named directly. These are closed sets defined in
    # our own schema, so they leak nothing and stay readable in the weights.
    features[f"source_{event.source.value}"] = 1.0
    features["severity_ordinal"] = SEVERITY_ORDINAL[event.severity]
    features[f"severity_{event.severity.value}"] = 1.0
    if event.direction is not None:
        features[f"direction_{event.direction.value}"] = 1.0
    else:
        features["direction_absent"] = 1.0

    # Presence flags. Which fields a sensor populated is itself signal, and it
    # costs no privacy to record that a field was set without recording what.
    features["has_user"] = 1.0 if event.user_id else 0.0
    features["has_process"] = 1.0 if event.process else 0.0
    features["has_asset"] = 1.0 if event.asset_id is not None else 0.0
    features["has_correlation"] = 1.0 if event.correlation_id is not None else 0.0
    features["metadata_richness"] = min(len(event.metadata), 10) / 10.0

    features.update(_port_features(event.src_port, "src"))
    features.update(_port_features(event.dst_port, "dst"))

    # Time of day as a cycle rather than a number, so 23:00 and 01:00 are near
    # each other. Off-hours activity is a weak but real signal.
    hour = event.timestamp.hour + event.timestamp.minute / 60.0
    radians = 2.0 * math.pi * hour / 24.0
    features["hour_sin"] = math.sin(radians)
    features["hour_cos"] = math.cos(radians)
    features["is_weekend"] = 1.0 if event.timestamp.weekday() >= 5 else 0.0

    # High-cardinality and attacker-influenced values, hashed.
    features[_bucket("event_type", event.event_type)] = 1.0
    if event.protocol:
        features[_bucket("protocol", event.protocol.lower())] = 1.0
    if event.src_ip is not None:
        features[_bucket("src_ip", str(event.src_ip))] = 1.0
    if event.dst_ip is not None:
        features[_bucket("dst_ip", str(event.dst_ip))] = 1.0
    if event.user_id:
        features[_bucket("user", event.user_id)] = 1.0
    if event.process:
        features[_bucket("process", event.process.lower())] = 1.0

    # Summary tokens, scaled by count so a verbose summary does not outweigh a
    # terse one purely by virtue of length.
    tokens = _tokenize_summary(event.summary)
    if tokens:
        share = 1.0 / len(tokens)
        for token in tokens:
            name = _bucket("summary", token)
            features[name] = features.get(name, 0.0) + share

    return features


def hash_to_dense(features: Mapping[str, float], dimension: int) -> list[float]:
    """Project a sparse feature mapping onto a fixed-width dense vector.

    The neural network needs a fixed input width. Signed hashing is used (each
    feature contributes with a deterministic +1 or -1 sign) so that collisions
    tend to cancel rather than accumulate, which is the standard correction for
    the bias feature hashing would otherwise introduce.
    """
    dense = [0.0] * dimension
    for name, value in features.items():
        digest = hashlib.blake2b(name.encode(), digest_size=8).digest()
        raw = int.from_bytes(digest, "big")
        index = raw % dimension
        sign = 1.0 if (raw >> 63) & 1 else -1.0
        dense[index] += sign * value
    return dense


def feature_names(events: Iterable[SecurityEvent]) -> set[str]:
    """Collect every feature name a batch of events produces.

    Useful for inspecting what the model can currently see, and for tests that
    assert extraction stays stable across releases.
    """
    names: set[str] = set()
    for event in events:
        names.update(extract_features(event))
    return names


__all__ = [
    "HASH_DIMENSION",
    "MAX_SUMMARY_TOKENS",
    "NOTABLE_PORTS",
    "SEVERITY_ORDINAL",
    "extract_features",
    "feature_names",
    "hash_to_dense",
]
