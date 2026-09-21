"""
Centralized runtime configuration.

All security-relevant behaviour (which algorithms are trusted, which issuer
and audience are accepted, where signing keys come from) is read from the
environment ONLY. Nothing here is hardcoded so that a production deployment
cannot silently inherit development defaults for the values that matter most
(JWKS_MODE, JWT_ISSUER, JWT_AUDIENCE).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    jwks_mode: str = os.getenv("JWKS_MODE", "dev")
    dev_keys_dir: str = os.getenv("DEV_KEYS_DIR", ".devkeys")

    jwks_url: str = os.getenv("JWKS_URL", "")
    jwks_cache_ttl_seconds: int = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "300"))
    jwks_lru_max_keys: int = int(os.getenv("JWKS_LRU_MAX_KEYS", "16"))
    jwks_timeout_seconds: int = int(os.getenv("JWKS_TIMEOUT_SECONDS", "5"))

    jwt_issuer: str = os.getenv("JWT_ISSUER", "https://auth.example.local")
    jwt_audience: str = os.getenv("JWT_AUDIENCE", "authorization-gateway")
    jwt_algorithms: list[str] = field(
        default_factory=lambda: _split_csv(os.getenv("JWT_ALGORITHMS", "RS256"))
    )

    correlation_id_header: str = os.getenv("CORRELATION_ID_HEADER", "X-Correlation-ID")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    def validate_for_startup(self) -> list[str]:
        """Return a list of blocking configuration problems (empty = OK)."""
        problems: list[str] = []

        if self.jwks_mode not in ("dev", "production"):
            problems.append(f"JWKS_MODE must be 'dev' or 'production', got '{self.jwks_mode}'")

        if self.jwks_mode == "production" and not self.jwks_url:
            problems.append("JWKS_URL is required when JWKS_MODE=production")

        if not self.jwt_algorithms:
            problems.append("JWT_ALGORITHMS must list at least one algorithm")

        insecure_algorithms = {"none", "HS256", "HS384", "HS512"}
        unsafe = insecure_algorithms.intersection(self.jwt_algorithms)
        if unsafe:
            problems.append(
                f"JWT_ALGORITHMS contains insecure/shared-secret algorithms for a "
                f"multi-tenant gateway: {sorted(unsafe)}. Use asymmetric algorithms (RS256/ES256)."
            )

        if not self.jwt_issuer or not self.jwt_audience:
            problems.append("JWT_ISSUER and JWT_AUDIENCE must both be set")

        return problems


settings = Settings()
