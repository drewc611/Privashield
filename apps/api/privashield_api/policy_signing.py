from __future__ import annotations

import base64
import hashlib
import json
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .policy_models import PolicyDocument, SignedPolicyEnvelope


def canonical_policy_payload(
    *,
    policy_id: UUID,
    version: int,
    document: PolicyDocument,
    key_id: str,
    algorithm: str = "ed25519",
) -> bytes:
    payload: dict[str, Any] = {
        "algorithm": algorithm,
        "document": document.model_dump(mode="json"),
        "key_id": key_id,
        "policy_id": str(policy_id),
        "version": version,
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def policy_content_digest(
    *,
    policy_id: UUID,
    version: int,
    document: PolicyDocument,
    key_id: str,
    algorithm: str = "ed25519",
) -> str:
    return hashlib.sha256(
        canonical_policy_payload(
            policy_id=policy_id,
            version=version,
            document=document,
            key_id=key_id,
            algorithm=algorithm,
        )
    ).hexdigest()


def encode_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def load_public_key(encoded: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ValueError("policy verification public key must be valid base64") from exc
    if len(raw) != 32:
        raise ValueError("policy verification public key must decode to 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def load_private_key_pem(pem: bytes, password: bytes | None = None) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("policy signing key must be an Ed25519 private key")
    return key


def sign_policy(
    *,
    policy_id: UUID,
    version: int,
    document: PolicyDocument,
    key_id: str,
    private_key: Ed25519PrivateKey,
) -> SignedPolicyEnvelope:
    payload = canonical_policy_payload(
        policy_id=policy_id,
        version=version,
        document=document,
        key_id=key_id,
    )
    signature = private_key.sign(payload).hex()
    return SignedPolicyEnvelope(
        policy_id=policy_id,
        version=version,
        document=document,
        key_id=key_id,
        signature=signature,
    )


def verify_policy(envelope: SignedPolicyEnvelope, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(
            bytes.fromhex(envelope.signature),
            canonical_policy_payload(
                policy_id=envelope.policy_id,
                version=envelope.version,
                document=envelope.document,
                key_id=envelope.key_id,
                algorithm=envelope.algorithm,
            ),
        )
    except (InvalidSignature, ValueError):
        return False
    return True
