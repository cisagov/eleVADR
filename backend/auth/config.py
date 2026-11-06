"""Environment-backed authentication configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class AuthConfig:
    """Runtime settings for the optional eleVADR authentication layer."""

    enabled: bool = False
    mongodb_uri: str = "mongodb://127.0.0.1:27017"
    mongodb_database: str = "elevadr"
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    pcap_retention_days: int = 0
    pcap_storage_limit_bytes: int = 0
    max_pcap_upload_bytes: int = 256 * 1024 * 1024
    cors_origins: tuple[str, ...] = ("http://127.0.0.1:5173", "http://localhost:5173")

    def validate_for_enabled_mode(self) -> None:
        """Reject unsafe/incomplete settings when authentication is enabled."""
        if not self.enabled:
            return
        if len(self.jwt_secret) < 32:
            raise ValueError("ELEVADR_JWT_SECRET must be at least 32 characters when authentication is enabled")
        if self.jwt_algorithm != "HS256":
            raise ValueError("ELEVADR_JWT_ALGORITHM must be HS256 in Stage 1")
        if self.jwt_expire_minutes < 1 or self.jwt_expire_minutes > 10080:
            raise ValueError("ELEVADR_JWT_EXPIRE_MINUTES must be between 1 and 10080")
        if not self.mongodb_uri.strip():
            raise ValueError("ELEVADR_MONGODB_URI is required when authentication is enabled")
        if self.pcap_retention_days < 0 or self.pcap_retention_days > 3650:
            raise ValueError("ELEVADR_PCAP_RETENTION_DAYS must be between 0 and 3650")
        if self.pcap_storage_limit_bytes < 0:
            raise ValueError("ELEVADR_PCAP_STORAGE_LIMIT_GB must be zero or greater")
        if self.max_pcap_upload_bytes < 1024 * 1024 or self.max_pcap_upload_bytes > 2 * 1024 * 1024 * 1024:
            raise ValueError("ELEVADR_MAX_PCAP_UPLOAD_MB must be between 1 and 2048")


def load_auth_config() -> AuthConfig:
    """Load authentication settings from environment variables."""
    raw_expiry = os.environ.get("ELEVADR_JWT_EXPIRE_MINUTES", "60")
    try:
        expiry = int(raw_expiry)
    except ValueError as exc:
        raise ValueError("ELEVADR_JWT_EXPIRE_MINUTES must be an integer") from exc
    raw_retention = os.environ.get("ELEVADR_PCAP_RETENTION_DAYS", "0")
    raw_limit_gb = os.environ.get("ELEVADR_PCAP_STORAGE_LIMIT_GB", "0")
    raw_upload_mb = os.environ.get("ELEVADR_MAX_PCAP_UPLOAD_MB", "256")
    try:
        retention = int(raw_retention)
        limit_bytes = int(float(raw_limit_gb) * 1024 * 1024 * 1024)
        max_upload_bytes = int(float(raw_upload_mb) * 1024 * 1024)
    except ValueError as exc:
        raise ValueError("PCAP retention/storage settings must be numeric") from exc
    config = AuthConfig(
        enabled=_env_bool("ELEVADR_AUTH_ENABLED", False),
        mongodb_uri=os.environ.get("ELEVADR_MONGODB_URI", "mongodb://127.0.0.1:27017"),
        mongodb_database=os.environ.get("ELEVADR_MONGODB_DATABASE", "elevadr"),
        jwt_secret=os.environ.get("ELEVADR_JWT_SECRET", ""),
        jwt_algorithm=os.environ.get("ELEVADR_JWT_ALGORITHM", "HS256"),
        jwt_expire_minutes=expiry,
        pcap_retention_days=retention,
        pcap_storage_limit_bytes=limit_bytes,
        max_pcap_upload_bytes=max_upload_bytes,
        cors_origins=tuple(x.strip().rstrip("/") for x in os.environ.get("ELEVADR_CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173").split(",") if x.strip()),
    )
    config.validate_for_enabled_mode()
    return config
