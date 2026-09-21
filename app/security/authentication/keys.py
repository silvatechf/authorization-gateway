"""
Development-only RSA keypair management.

This module exists so the gateway can be run and tested end-to-end without a
real identity provider. It is NEVER used when JWKS_MODE=production. The
keypair is generated once and persisted to disk (DEV_KEYS_DIR) so that
restarting the app does not invalidate previously issued dev tokens.
"""
from __future__ import annotations

import base64
import json
import os
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_PRIVATE_KEY_FILE = "private_key.pem"
_PUBLIC_KEY_FILE = "public_key.pem"
_KID_FILE = "kid.txt"


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def ensure_dev_keypair(keys_dir: str) -> None:
    """Generate an RSA-2048 keypair + kid under keys_dir if none exists yet."""
    os.makedirs(keys_dir, exist_ok=True)
    private_path = os.path.join(keys_dir, _PRIVATE_KEY_FILE)
    public_path = os.path.join(keys_dir, _PUBLIC_KEY_FILE)
    kid_path = os.path.join(keys_dir, _KID_FILE)

    if os.path.exists(private_path) and os.path.exists(public_path) and os.path.exists(kid_path):
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(private_path, "wb") as fh:
        fh.write(private_pem)
    with open(public_path, "wb") as fh:
        fh.write(public_pem)
    with open(kid_path, "w") as fh:
        fh.write(str(uuid.uuid4()))

    # Private key must not be group/world readable.
    os.chmod(private_path, 0o600)


def load_private_key_pem(keys_dir: str) -> bytes:
    with open(os.path.join(keys_dir, _PRIVATE_KEY_FILE), "rb") as fh:
        return fh.read()


def load_public_key_pem(keys_dir: str) -> bytes:
    with open(os.path.join(keys_dir, _PUBLIC_KEY_FILE), "rb") as fh:
        return fh.read()


def load_kid(keys_dir: str) -> str:
    with open(os.path.join(keys_dir, _KID_FILE)) as fh:
        return fh.read().strip()


def build_jwks(keys_dir: str) -> dict:
    """Build a JWKS document (RFC 7517) for the dev public key."""
    public_pem = load_public_key_pem(keys_dir)
    public_key = serialization.load_pem_public_key(public_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        # We only ever generate RSA keypairs ourselves (see
        # ensure_dev_keypair), so this would indicate a corrupted or
        # hand-edited .devkeys directory, not a real runtime path.
        raise ValueError("Dev public key is not an RSA key")
    numbers = public_key.public_numbers()

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": load_kid(keys_dir),
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }
    return {"keys": [jwk]}


def build_jwks_json(keys_dir: str) -> str:
    return json.dumps(build_jwks(keys_dir))
