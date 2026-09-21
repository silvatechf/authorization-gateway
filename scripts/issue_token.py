"""
Dev-only helper: mint a demo JWT for one of the seeded users in
app/data/store.py, signed with the locally generated dev keypair.

    python -m scripts.issue_token --user user-a1
    python -m scripts.issue_token --user admin-a --ttl 3600

This script refuses to run when JWKS_MODE=production, since there is no
"issuing" to do against a real IdP — get a real token from your IdP
instead.
"""
from __future__ import annotations

import argparse
import time

import jwt as pyjwt

from app.config import settings
from app.data.store import get_user
from app.security.authentication import keys as dev_keys


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a demo JWT for local testing.")
    parser.add_argument("--user", help="Seeded user id, e.g. user-a1, admin-a, user-b1")
    parser.add_argument("--ttl", type=int, default=900, help="Token lifetime in seconds")
    parser.add_argument(
        "--generate-keys-only",
        action="store_true",
        help="Only (re)generate the dev keypair, do not issue a token",
    )
    args = parser.parse_args()

    if settings.jwks_mode != "dev":
        raise SystemExit("Refusing to issue dev tokens while JWKS_MODE != 'dev'.")

    dev_keys.ensure_dev_keypair(settings.dev_keys_dir)

    if args.generate_keys_only:
        print(f"Dev keypair ready in {settings.dev_keys_dir}")
        return

    if not args.user:
        raise SystemExit("--user is required unless --generate-keys-only is passed")

    user = get_user(args.user)
    if user is None:
        raise SystemExit(f"Unknown seeded user id: {args.user}")

    now = int(time.time())
    claims = {
        "sub": user.id,
        "tenant_id": user.tenant_id,
        "roles": user.roles,
        "scopes": user.scopes,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + args.ttl,
    }

    private_pem = dev_keys.load_private_key_pem(settings.dev_keys_dir)
    kid = dev_keys.load_kid(settings.dev_keys_dir)

    token = pyjwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})
    print(token)


if __name__ == "__main__":
    main()
