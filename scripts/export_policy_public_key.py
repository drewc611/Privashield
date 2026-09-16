from __future__ import annotations

import argparse
import os
from pathlib import Path

from privashield_api.policy_signing import encode_public_key, load_private_key_pem


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Export a PrivaShield Ed25519 policy verification key as base64."
    )
    value.add_argument("--private-key", required=True, type=Path, help="Ed25519 PEM private key")
    return value


def main() -> int:
    args = parser().parse_args()
    password_text = os.getenv("PRIVASHIELD_POLICY_SIGNING_KEY_PASSWORD")
    password = password_text.encode("utf-8") if password_text else None
    private_key = load_private_key_pem(args.private_key.read_bytes(), password=password)
    print(encode_public_key(private_key.public_key()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
