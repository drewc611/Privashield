from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any
from uuid import UUID

from .policy_models import PolicyDocument, SignedPolicyEnvelope


def canonical_policy_payload(
    *,
    policy_id: UUID,
    version: int,
    document: PolicyDocument,
    key_id: str,
    algorithm: str = "hmac-sha256",
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
    algorithm: str = "hmac-sha256",
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


def sign_policy(
    *,
    policy_id: UUID,
    version: int,
    document: PolicyDocument,
    key_id: str,
    signing_key: bytes,
) -> SignedPolicyEnvelope:
    if not signing_key:
        raise ValueError("policy signing key must not be empty")
    payload = canonical_policy_payload(
        policy_id=policy_id,
        version=version,
        document=document,
        key_id=key_id,
    )
    signature = hmac.new(signing_key, payload, hashlib.sha256).hexdigest()
    return SignedPolicyEnvelope(
        policy_id=policy_id,
        version=version,
        document=document,
        key_id=key_id,
        signature=signature,
    )


def verify_policy(envelope: SignedPolicyEnvelope, signing_key: bytes) -> bool:
    if not signing_key:
        return False
    expected = hmac.new(
        signing_key,
        canonical_policy_payload(
            policy_id=envelope.policy_id,
            version=envelope.version,
            document=envelope.document,
            key_id=envelope.key_id,
            algorithm=envelope.algorithm,
        ),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, envelope.signature)
