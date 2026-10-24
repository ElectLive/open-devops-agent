"""
Bearer-token authorization for the management API (org config, docs, audit).

- ``API_ADMIN_TOKEN``: platform operator token, valid for every org.
- ``API_ORG_TOKENS``: per-org tokens, ``org-a=token-a,org-b=token-b``; each is
  valid only for its own org.
- Fails closed: with neither configured, protected routes return 503 unless
  ``API_AUTH_DISABLED=true`` is set explicitly (local development only).

Webhooks keep their own signature checks (``api.webhook_auth``) and ``/health``
stays open for liveness probes.
"""
from __future__ import annotations

import os
from typing import Dict, Optional

from fastapi import HTTPException

from api.webhook_auth import _signatures_equal, bearer_token


def api_auth_disabled() -> bool:
    return os.getenv("API_AUTH_DISABLED", "false").strip().lower() in ("true", "1", "yes")


def _admin_token() -> str:
    return os.getenv("API_ADMIN_TOKEN", "").strip()


def _org_tokens() -> Dict[str, str]:
    """Parse API_ORG_TOKENS (``org=token`` pairs, comma-separated)."""
    tokens: Dict[str, str] = {}
    for pair in os.getenv("API_ORG_TOKENS", "").split(","):
        org, sep, token = pair.partition("=")
        if sep and org.strip() and token.strip():
            tokens[org.strip()] = token.strip()
    return tokens


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"}
    )


def require_org_access(org_id: str, authorization: Optional[str]) -> None:
    """Allow the request only for the admin token or the token of ``org_id``.

    Raises 503 when no tokens are configured, 401 for a missing or unknown
    token, and 403 for a valid token belonging to a different org.
    """
    if api_auth_disabled():
        return

    admin = _admin_token()
    org_tokens = _org_tokens()
    if not admin and not org_tokens:
        raise HTTPException(
            status_code=503,
            detail=(
                "API authentication is not configured. Set API_ADMIN_TOKEN or "
                "API_ORG_TOKENS (or API_AUTH_DISABLED=true for local development)."
            ),
        )

    token = bearer_token(authorization)
    if not token:
        raise _unauthorized("Bearer token required")

    if admin and _signatures_equal(admin, token):
        return

    # Compare against every org token so timing does not reveal which org matched.
    matched_orgs = [org for org, expected in org_tokens.items() if _signatures_equal(expected, token)]
    if org_id in matched_orgs:
        return
    if matched_orgs:
        raise HTTPException(status_code=403, detail="Token is not valid for this organization")
    raise _unauthorized("Invalid token")
