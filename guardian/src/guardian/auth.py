"""
Guardian Authentication — API Key + mTLS Support

Provides configurable authentication for the Guardian API:
  1. API Key (Bearer token) — default, simple, good for dev/staging
  2. mTLS (mutual TLS) — certificate-based, for enterprise production
  3. Combined — both API key and client certificate required

mTLS configuration:
  Guardian doesn't terminate TLS itself — it reads client certificate
  info from headers set by the reverse proxy (Nginx, Envoy, Traefik).
  The proxy terminates TLS, validates the client cert against a CA,
  and passes the subject/fingerprint via headers.

Environment variables:
  GUARDIAN_API_KEY          — API key (empty = no auth in dev mode)
  GUARDIAN_MTLS_ENABLED     — "true" to enable mTLS verification
  GUARDIAN_MTLS_HEADER      — Header containing client cert subject
                              (default: X-Client-Cert-Subject)
  GUARDIAN_MTLS_ALLOWED_CNS — Comma-separated list of allowed Common Names
                              (empty = any valid cert is accepted)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    """Authentication configuration."""
    api_key: str = ""
    mtls_enabled: bool = False
    mtls_header: str = "X-Client-Cert-Subject"
    mtls_fingerprint_header: str = "X-Client-Cert-Fingerprint"
    mtls_allowed_cns: list[str] | None = None  # None = any valid cert

    @classmethod
    def from_env(cls) -> "AuthConfig":
        allowed_cns_raw = os.getenv("GUARDIAN_MTLS_ALLOWED_CNS", "")
        allowed_cns = [cn.strip() for cn in allowed_cns_raw.split(",") if cn.strip()] or None

        return cls(
            api_key=os.getenv("GUARDIAN_API_KEY", ""),
            mtls_enabled=os.getenv("GUARDIAN_MTLS_ENABLED", "").lower() == "true",
            mtls_header=os.getenv("GUARDIAN_MTLS_HEADER", "X-Client-Cert-Subject"),
            mtls_fingerprint_header=os.getenv("GUARDIAN_MTLS_FINGERPRINT_HEADER", "X-Client-Cert-Fingerprint"),
            mtls_allowed_cns=allowed_cns,
        )


class Authenticator:
    """
    Request authenticator supporting API key and mTLS.

    Usage in FastAPI:
        auth = Authenticator(AuthConfig.from_env())

        @app.post("/v1/evaluate")
        def evaluate(request: Request, _: None = Depends(auth.verify)):
            ...
    """

    def __init__(self, config: AuthConfig):
        self.config = config
        if config.mtls_enabled:
            logger.info(
                "mTLS authentication enabled (header: %s, allowed CNs: %s)",
                config.mtls_header,
                config.mtls_allowed_cns or "any",
            )

    def verify(self, request: Request) -> None:
        """
        Verify the request against configured authentication methods.

        Raises HTTPException(401) if authentication fails.
        """
        # API key check (if configured)
        if self.config.api_key:
            auth_header = request.headers.get("Authorization", "")
            if auth_header != f"Bearer {self.config.api_key}":
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or missing API key",
                )

        # mTLS check (if enabled)
        if self.config.mtls_enabled:
            self._verify_mtls(request)

    def _verify_mtls(self, request: Request) -> None:
        """Verify client certificate from reverse proxy headers."""
        cert_subject = request.headers.get(self.config.mtls_header, "")
        cert_fingerprint = request.headers.get(self.config.mtls_fingerprint_header, "")

        if not cert_subject:
            raise HTTPException(
                status_code=401,
                detail=(
                    f"mTLS required: no client certificate found. "
                    f"Expected header: {self.config.mtls_header}"
                ),
            )

        # Extract CN from subject (format: "CN=service-name,O=org,...")
        cn = self._extract_cn(cert_subject)
        if not cn:
            raise HTTPException(
                status_code=401,
                detail=f"mTLS: could not extract CN from subject: {cert_subject}",
            )

        # Check against allowed CNs (if configured)
        if self.config.mtls_allowed_cns:
            if cn not in self.config.mtls_allowed_cns:
                logger.warning(
                    "mTLS rejected: CN=%s not in allowed list (fingerprint=%s)",
                    cn, cert_fingerprint,
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"mTLS: CN '{cn}' not authorized",
                )

        logger.debug("mTLS verified: CN=%s fingerprint=%s", cn, cert_fingerprint)

    @staticmethod
    def _extract_cn(subject: str) -> str:
        """Extract Common Name from certificate subject string."""
        # Handle formats: "CN=name,O=org" or "/CN=name/O=org" or "CN = name, O = org"
        for part in subject.replace("/", ",").split(","):
            part = part.strip()
            if part.upper().startswith("CN=") or part.upper().startswith("CN ="):
                return part.split("=", 1)[1].strip()
        return ""

    def get_client_identity(self, request: Request) -> str | None:
        """
        Extract the authenticated client identity from the request.

        Returns the CN from the client cert (mTLS) or None (API key only).
        Useful for audit logging — knowing which service called Guardian.
        """
        if self.config.mtls_enabled:
            cert_subject = request.headers.get(self.config.mtls_header, "")
            return self._extract_cn(cert_subject) or None
        return None
