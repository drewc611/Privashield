from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from uuid import UUID

from privashield_api.policy_models import PolicyDocument
from privashield_api.policy_signing import load_private_key_pem, sign_policy


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Create an Ed25519-signed PrivaShield policy envelope offline."
    )
    value.add_argument("--document", required=True, type=Path, help="PolicyDocument JSON file")
    value.add_argument("--private-key", required=True, type=Path, help="Ed25519 PEM private key")
    value.add_argument("--policy-id", required=True, type=UUID)
    value.add_argument("--version", required=True, type=int)
    value.add_argument(
        "--key-id",
        default=os.getenv("PRIVASHIELD_POLICY_VERIFICATION_KEY_ID", "local-v1"),
    )
    return value


def main() -> int:
    args = parser().parse_args()
    if args.version < 1:
        raise SystemExit("--version must be at least 1")

    password_text = os.getenv("PRIVASHIELD_POLICY_SIGNING_KEY_PASSWORD")
    password = password_text.encode("utf-8") if password_text else None
    private_key = load_private_key_pem(args.private_key.read_bytes(), password=password)
    document = PolicyDocument.model_validate_json(args.document.read_text(encoding="utf-8"))
    envelope = sign_policy(
        policy_id=args.policy_id,
        version=args.version,
        document=document,
        key_id=args.key_id,
        private_key=private_key,
    )
    print(json.dumps(envelope.model_dump(mode="json"), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
