"""
Edge middleware — thin connector between your network and the central DevOps AI Agent.

Deploy this instead of the full agent on every host:
  alerts/CI  →  middleware  →  central agent (open-source)
  central agent  →  middleware /exec  →  local allowlisted commands (optional)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import shlex
from typing import Any

import httpx
import structlog
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

log = structlog.get_logger()

_DEFAULT_ALLOW = (
    r"^docker\s+(ps|logs|inspect|restart)\b,"
    r"^systemctl\s+(status|restart|reload)\s+(nginx|docker)\b,"
    r"^nginx\s+-t$,"
    r"^df\s+-h$,"
    r"^journalctl\b,"
    r"^kubectl\s+(get|describe|logs|rollout)\b"
)

_BLOCKED = re.compile(
    r"(?i)(\brm\s+-rf\b|\bmkfs\b|\bdd\s+if=|\bshutdown\b|\breboot\b|"
    r"\bcurl\s+[^\n]*\|\s*(ba)?sh\b|>\s*/dev/sd|chmod\s+-R\s+777)"
)

app = FastAPI(
    title="DevOps Agent Edge Middleware",
    description="Forward incidents to the central agent; optional allowlisted local exec.",
    version="1.0.0",
)


class ExecRequest(BaseModel):
    command: str = Field(..., min_length=1, max_length=2000)
    cwd: str | None = None


def _cfg(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _agent_base() -> str:
    return _cfg("AGENT_BASE_URL").rstrip("/")


def _agent_secret() -> str:
    return _cfg("AGENT_WEBHOOK_SECRET") or _cfg("WEBHOOK_SECRET")


def _middleware_token() -> str:
    return _cfg("MIDDLEWARE_AUTH_TOKEN")


def _org_id() -> str:
    return _cfg("ORG_ID", "default")


def _default_host() -> str:
    return _cfg("MIDDLEWARE_DEFAULT_HOST")


def _forward_path() -> str:
    return _cfg("AGENT_FORWARD_PATH", "/webhook/manual")


def _exec_enabled() -> bool:
    return _cfg("MIDDLEWARE_EXEC_ENABLED", "false").lower() in ("true", "1", "yes")


def _exec_timeout() -> int:
    try:
        return int(_cfg("MIDDLEWARE_EXEC_TIMEOUT", "60"))
    except ValueError:
        return 60


def _allowlist() -> list[re.Pattern[str]]:
    raw = _cfg("MIDDLEWARE_EXEC_ALLOWLIST", _DEFAULT_ALLOW)
    return [re.compile(p.strip()) for p in raw.split(",") if p.strip()]


def _sign(body: bytes) -> str:
    secret = _agent_secret()
    if not secret:
        return ""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _require_middleware_auth(
    authorization: str | None, x_middleware_token: str | None
) -> None:
    expected = _middleware_token()
    if not expected:
        return
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    elif x_middleware_token:
        token = x_middleware_token.strip()
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid middleware token")


def _command_allowed(command: str) -> bool:
    cmd = command.strip()
    if not cmd or _BLOCKED.search(cmd):
        return False
    return any(p.search(cmd) for p in _allowlist())


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "agent_configured": bool(_agent_base()),
        "exec_enabled": _exec_enabled(),
        "org_id": _org_id(),
    }


@app.post("/forward")
@app.post("/webhook")
@app.post("/webhook/{source}")
async def forward_incident(
    request: Request,
    source: str | None = None,
    x_org_id: str | None = Header(None, alias="X-Org-ID"),
    authorization: str | None = Header(None),
    x_middleware_token: str | None = Header(None, alias="X-Middleware-Token"),
):
    """Accept an incident/alert payload and forward it to the central agent."""
    _require_middleware_auth(authorization, x_middleware_token)

    base = _agent_base()
    if not base:
        raise HTTPException(status_code=503, detail="AGENT_BASE_URL is not configured")

    raw = await request.body()
    try:
        payload: Any = json.loads(raw.decode() or "{}")
    except Exception as exc:
        raise HTTPException(status_code=400, detail="JSON body required") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON object required")

    if "type" not in payload:
        payload = {
            "type": payload.get("issue_type") or "server",
            "description": payload.get("description")
            or payload.get("summary")
            or "Forwarded by middleware",
            "raw_logs": payload.get("raw_logs") or payload.get("message"),
            "labels": payload.get("labels") or {},
            **{k: v for k, v in payload.items() if k not in ("issue_type",)},
        }

    payload.setdefault("source", source or "middleware")
    payload["org_id"] = x_org_id or payload.get("org_id") or _org_id()
    host = _default_host()
    if host and not payload.get("host"):
        payload["host"] = host
    payload.setdefault("labels", {})
    if isinstance(payload["labels"], dict):
        payload["labels"].setdefault("via_middleware", "true")

    body = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "X-Org-ID": str(payload["org_id"]),
        "User-Agent": "devops-agent-middleware/1.0",
    }
    sig = _sign(body)
    if sig:
        headers["X-Hub-Signature-256"] = sig
        headers["X-Webhook-Signature"] = sig

    url = f"{base}{_forward_path()}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        log.error("forward_failed", error=str(exc), url=url)
        raise HTTPException(status_code=502, detail=f"Failed to reach agent: {exc}") from exc

    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text}

    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=data)

    return {
        "status": "forwarded",
        "agent_status": resp.status_code,
        "agent_response": data,
        "org_id": payload["org_id"],
    }


@app.post("/exec")
async def exec_local(
    body: ExecRequest,
    authorization: str | None = Header(None),
    x_middleware_token: str | None = Header(None, alias="X-Middleware-Token"),
):
    """
    Optional callback for the central agent when it cannot SSH in.
    Only allowlisted, non-destructive commands run.
    """
    _require_middleware_auth(authorization, x_middleware_token)

    if not _exec_enabled():
        raise HTTPException(
            status_code=403,
            detail="Local exec disabled. Set MIDDLEWARE_EXEC_ENABLED=true to allow.",
        )

    command = body.command.strip()
    if not _command_allowed(command):
        raise HTTPException(
            status_code=403,
            detail="Command blocked by middleware allowlist / safety filter",
        )

    try:
        proc = await asyncio.create_subprocess_exec(
            *shlex.split(command),
            cwd=body.cwd or None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_exec_timeout()
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise HTTPException(status_code=504, detail="Command timed out") from None
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {
        "success": proc.returncode == 0,
        "exit_code": proc.returncode,
        "stdout": (stdout or b"").decode(errors="replace")[-20000:],
        "stderr": (stderr or b"").decode(errors="replace")[-8000:],
        "command": command,
    }
