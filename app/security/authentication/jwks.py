"""
Key resolution for JWT signature verification.

Two providers implement the same interface (`resolve_key`):

- DevKeyProvider: reads the locally generated RSA keypair. Used only when
  JWKS_MODE=dev. Rejects any token whose `kid` does not match the single
  dev key, so a stale/forged kid fails closed instead of silently
  succeeding against "the only key we have".

- ProductionJWKSProvider: wraps PyJWT's PyJWKClient, which already
  implements JWKS caching (TTL) and an LRU cache of individual signing
  keys, keyed by `kid`. We do not reimplement that caching ourselves.
"""
from __future__ import annotations

from typing import Any

from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError

from app.security.authentication import keys as dev_keys


class KeyResolutionError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class DevKeyProvider:
    def __init__(self, keys_dir: str) -> None:
        self._keys_dir = keys_dir
        dev_keys.ensure_dev_keypair(keys_dir)

    def resolve_key(self, token: str, unverified_kid: str | None) -> Any:
        expected_kid = dev_keys.load_kid(self._keys_dir)
        if unverified_kid != expected_kid:
            raise KeyResolutionError("UNKNOWN_KID", "Token key id does not match a known signing key")
        public_pem = dev_keys.load_public_key_pem(self._keys_dir)
        return public_pem


class ProductionJWKSProvider:
    def __init__(
        self, jwks_url: str, cache_ttl_seconds: int, lru_max_keys: int, timeout_seconds: int,
    ) -> None:
        # PyJWKClient handles JWKS fetch caching (lifespan) and a per-kid
        # LRU cache (max_cached_keys) natively.
        self._client = PyJWKClient(
            uri=jwks_url,
            cache_keys=True,
            max_cached_keys=lru_max_keys,
            lifespan=cache_ttl_seconds,
            timeout=timeout_seconds,
        )

    def resolve_key(self, token: str, unverified_kid: str | None) -> Any:
        try:
            signing_key = self._client.get_signing_key_from_jwt(token)
        except PyJWKClientError as exc:
            raise KeyResolutionError("UNKNOWN_KID", str(exc)) from exc
        return signing_key.key
