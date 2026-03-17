"""
Intune Identity Resolver

Extracts actor identity from the Azure AD Bearer token on inbound
Graph API requests. In production, this validates the JWT against
Azure AD's public keys. For the proxy pattern, the token is also
forwarded to the real Graph API if the action is allowed.
"""

from __future__ import annotations

import base64
import json
import logging

from guardian.adapters.identity import IdentityResolver, ResolvedIdentity
from guardian.adapters.intune.models import IntuneCallerIdentity

logger = logging.getLogger(__name__)


class IntuneIdentityResolver(IdentityResolver):
    """
    Resolve actor identity from Azure AD JWT in the Authorization header.

    In a production deployment, this should validate the JWT signature
    against Azure AD's JWKS endpoint. For the initial implementation,
    we decode the payload without verification (the real Graph API will
    reject invalid tokens anyway — Guardian is not the auth boundary).
    """

    def resolve(self, request_context: dict) -> ResolvedIdentity:
        """
        Extract identity from request context.

        Expected keys:
          - authorization: str — the full Authorization header value
          - tenant_id: str — Azure AD tenant (from config or token)
        """
        auth_header = request_context.get("authorization", "")
        tenant_id = request_context.get("tenant_id", "unknown")

        if not auth_header.startswith("Bearer "):
            return ResolvedIdentity(
                actor_name="unknown-intune-actor",
                actor_source="intune_azure_ad",
                authenticated=False,
                confidence=0.0,
            )

        token = auth_header[len("Bearer "):]
        caller = self._decode_token_claims(token)

        if not caller:
            return ResolvedIdentity(
                actor_name="unknown-intune-actor",
                actor_source="intune_azure_ad",
                authenticated=False,
                raw_principal=f"token_present tenant={tenant_id}",
                confidence=0.1,
            )

        actor_name = f"intune-{caller.tenant_id}-{caller.user_principal_name}"

        return ResolvedIdentity(
            actor_name=actor_name,
            actor_source="intune_azure_ad",
            authenticated=True,
            raw_principal=(
                f"upn={caller.user_principal_name} "
                f"oid={caller.object_id} "
                f"tenant={caller.tenant_id}"
            ),
            confidence=0.9,  # Azure AD authenticated, but JWT not locally verified
        )

    def _decode_token_claims(self, token: str) -> IntuneCallerIdentity | None:
        """
        Decode JWT payload (without signature verification).

        Production deployments should validate against Azure AD JWKS.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Decode the payload (second segment)
            payload = parts[1]
            # Add padding
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            decoded = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded)

            return IntuneCallerIdentity(
                user_principal_name=claims.get("upn", claims.get("unique_name", "")),
                object_id=claims.get("oid", ""),
                tenant_id=claims.get("tid", ""),
                display_name=claims.get("name", ""),
                roles=claims.get("roles", []),
            )
        except Exception:
            logger.debug("Failed to decode JWT claims", exc_info=True)
            return None
