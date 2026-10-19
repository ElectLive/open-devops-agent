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
from collections.abc import Callable
from typing import Any

import httpx
import structlog
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

log = structlog.get_logger()

_BLOCKED = re.compile(
    r"(?i)(\brm\s+-rf\b|\bmkfs\b|\bdd\s+if=|\bshutdown\b|\breboot\b|"
    r"\bcurl\s+[^\n]*\|\s*(ba)?sh\b|>\s*/dev/sd|chmod\s+-R\s+777)"
)

_EXEC_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_EXEC_UNIT = re.compile(r"[A-Za-z0-9_.@:-]{1,128}")
_KUBECTL_RESOURCE_ALIASES = {
    "all": "all",
    "pod": "pods",
    "pods": "pods",
    "po": "pods",
    "deployment": "deployments",
    "deployments": "deployments",
    "deploy": "deployments",
    "replicaset": "replicasets",
    "replicasets": "replicasets",
    "rs": "replicasets",
    "statefulset": "statefulsets",
    "statefulsets": "statefulsets",
    "sts": "statefulsets",
    "daemonset": "daemonsets",
    "daemonsets": "daemonsets",
    "ds": "daemonsets",
    "service": "services",
    "services": "services",
    "svc": "services",
    "node": "nodes",
    "nodes": "nodes",
    "no": "nodes",
    "event": "events",
    "events": "events",
    "ev": "events",
    "job": "jobs",
    "jobs": "jobs",
    "cronjob": "cronjobs",
    "cronjobs": "cronjobs",
    "cj": "cronjobs",
    "namespace": "namespaces",
    "namespaces": "namespaces",
    "ns": "namespaces",
    "secret": "secrets",
    "secrets": "secrets",
    "sec": "secrets",
    "configmap": "configmaps",
    "configmaps": "configmaps",
    "cm": "configmaps",
}
_KUBECTL_GET_RESOURCES = {
    "all",
    "pods",
    "deployments",
    "replicasets",
    "statefulsets",
    "daemonsets",
    "services",
    "nodes",
    "events",
    "jobs",
    "cronjobs",
    "namespaces",
}
_KUBECTL_DESCRIBE_RESOURCES = {"nodes", "services", "events", "namespaces"}
_DISALLOWED_EXEC_FLAGS = {
    "--kubeconfig",
    "--server",
    "--token",
    "--host",
    "--context",
    "--user",
    "--cluster",
    "--as",
    "--as-group",
    "--as-uid",
    "--username",
    "--password",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--insecure-skip-tls-verify",
    "--config",
    "--tls",
    "--tlsverify",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
}

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


def _allowlist() -> list[re.Pattern[str]] | None:
    raw = _cfg("MIDDLEWARE_EXEC_ALLOWLIST")
    if not raw.strip():
        return None
    try:
        patterns = [pattern.strip() for pattern in raw.split(",")]
        return [re.compile(pattern) for pattern in patterns if pattern]
    except re.error:
        return []


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


def _parse_options(
    arguments: list[str],
    switches: set[str],
    value_options: dict[str, Callable[[str], bool]],
) -> list[str] | None:
    positionals: list[str] = []
    seen_options: set[str] = set()
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if not token.startswith("-"):
            positionals.append(token)
            index += 1
            continue

        option, separator, value = token.partition("=")
        if option in switches and not separator and option not in seen_options:
            seen_options.add(option)
            index += 1
            continue

        validator = value_options.get(option)
        if validator is None or option in seen_options:
            return None
        if not separator:
            index += 1
            if index >= len(arguments):
                return None
            value = arguments[index]
        if not validator(value):
            return None
        seen_options.add(option)
        index += 1

    return positionals


def _is_identifier(value: str) -> bool:
    return _EXEC_IDENTIFIER.fullmatch(value) is not None


def _is_bounded_integer(value: str, maximum: int = 10000) -> bool:
    if not re.fullmatch(r"[0-9]{1,5}", value):
        return False
    return 1 <= int(value) <= maximum


def _is_safe_time_filter(value: str) -> bool:
    return (
        len(value) <= 80
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .:+/_-]*", value) is not None
    )


def _is_duration(value: str) -> bool:
    match = re.fullmatch(r"([1-9][0-9]{0,4})(ms|s|m|h)", value)
    if match is None:
        return False
    maximum = {"ms": 3600000, "s": 86400, "m": 1440, "h": 24}[match.group(2)]
    return int(match.group(1)) <= maximum


def _is_selector(value: str) -> bool:
    return (
        len(value) <= 256
        and re.fullmatch(r"[A-Za-z0-9_.!:=,()/+-]+", value) is not None
    )


def _kubectl_resource_allowed(target: str, resources: set[str]) -> bool:
    resource, separator, name = target.partition("/")
    canonical = _KUBECTL_RESOURCE_ALIASES.get(resource.lower())
    if canonical not in resources:
        return False
    if separator:
        return canonical != "all" and _is_identifier(name)
    return True


def _kubectl_command_allowed(arguments: list[str]) -> bool:
    if len(arguments) < 2:
        return False
    subcommand = arguments[1]

    if subcommand in {"get", "describe"}:
        switches = {"-A", "--all-namespaces"}
        value_options: dict[str, Callable[[str], bool]] = {
            "-n": _is_identifier,
            "--namespace": _is_identifier,
            "-l": _is_selector,
            "--selector": _is_selector,
        }
        if subcommand == "get":
            switches.update({"--show-labels", "--no-headers"})
            value_options.update(
                {
                    "-o": lambda value: value in {"wide", "name"},
                    "--output": lambda value: value in {"wide", "name"},
                }
            )
        positionals = _parse_options(arguments[1:], switches, value_options)
        if positionals is None:
            return False
        if len(positionals) < 2 or positionals[0] != subcommand:
            return False
        resources = (
            _KUBECTL_GET_RESOURCES
            if subcommand == "get"
            else _KUBECTL_DESCRIBE_RESOURCES
        )
        return _kubectl_resource_allowed(positionals[1], resources) and all(
            _is_identifier(name) for name in positionals[2:]
        )

    if subcommand == "logs":
        positionals = _parse_options(
            arguments[1:],
            {"--timestamps", "--previous"},
            {
                "-n": _is_identifier,
                "--namespace": _is_identifier,
                "-c": _is_identifier,
                "--container": _is_identifier,
                "--tail": _is_bounded_integer,
                "--since": _is_duration,
                "--since-time": _is_safe_time_filter,
            },
        )
        if positionals is None:
            return False
        if len(positionals) != 2 or positionals[0] != "logs":
            return False
        target = positionals[1]
        if "/" not in target:
            return _is_identifier(target)
        return _kubectl_resource_allowed(target, {"pods", "deployments"})

    if subcommand == "rollout":
        positionals = _parse_options(
            arguments[1:],
            set(),
            {
                "-n": _is_identifier,
                "--namespace": _is_identifier,
                "--timeout": _is_duration,
                "--watch": lambda value: value == "false",
            },
        )
        return (
            positionals is not None
            and len(positionals) == 3
            and positionals[:2] == ["rollout", "status"]
            and _kubectl_resource_allowed(
                positionals[2], {"deployments", "daemonsets", "statefulsets"}
            )
        )

    return False


def _journalctl_command_allowed(arguments: list[str]) -> bool:
    switches = {"--no-pager", "-b", "--boot"}
    value_options: dict[str, Callable[[str], bool]] = {
        "-u": lambda value: _EXEC_UNIT.fullmatch(value) is not None,
        "--unit": lambda value: _EXEC_UNIT.fullmatch(value) is not None,
        "-n": _is_bounded_integer,
        "--lines": _is_bounded_integer,
        "--since": _is_safe_time_filter,
        "--until": _is_safe_time_filter,
    }
    positionals = _parse_options(arguments[1:], switches, value_options)
    if positionals is None or positionals:
        return False
    filtering_options = {"-u", "--unit", "-n", "--lines", "--since"}
    return any(
        option in filtering_options
        or option.startswith(tuple(f"{name}=" for name in filtering_options))
        for option in arguments[1:]
    )


def _default_command_allowed(arguments: list[str]) -> bool:
    command = arguments[0]
    if command == "docker" and len(arguments) >= 2:
        if arguments[1] == "ps":
            positionals = _parse_options(
                arguments[2:],
                {"-a", "--all", "--no-trunc", "--size", "-q", "--quiet"},
                {},
            )
            return positionals == []
        if arguments[1] == "logs":
            positionals = _parse_options(
                arguments[2:],
                {"--timestamps"},
                {
                    "--tail": _is_bounded_integer,
                    "--since": _is_safe_time_filter,
                    "--until": _is_safe_time_filter,
                },
            )
            return (
                positionals is not None
                and len(positionals) == 1
                and _is_identifier(positionals[0])
            )
        return False

    if command == "systemctl":
        positionals = _parse_options(
            arguments[1:],
            {"--no-pager"},
            {"-n": _is_bounded_integer, "--lines": _is_bounded_integer},
        )
        if positionals is None or len(positionals) < 2:
            return False
        services = positionals[1:]
        return positionals[0] == "status" and all(
            service in {"nginx", "docker"} for service in services
        )

    if command == "nginx":
        return arguments == ["nginx", "-t"]

    if command == "df":
        return arguments == ["df", "-h"]

    if command == "journalctl":
        return _journalctl_command_allowed(arguments)

    if command == "kubectl":
        return _kubectl_command_allowed(arguments)

    return False


def _has_disallowed_exec_flags(arguments: list[str]) -> bool:
    for argument in arguments:
        option = argument.partition("=")[0]
        if option in _DISALLOWED_EXEC_FLAGS:
            return True
        if argument.startswith(("-H", "-s")):
            return True
    return False


def _command_allowed(command: str, arguments: list[str]) -> bool:
    cmd = command.strip()
    has_control_character = any(
        (ord(char) < 32 and char != "\t") or ord(char) == 127 for char in cmd
    )
    if (
        not cmd
        or not arguments
        or _BLOCKED.search(cmd)
        or _has_disallowed_exec_flags(arguments)
        or has_control_character
    ):
        return False
    custom_allowlist = _allowlist()
    if custom_allowlist is not None:
        for pattern in custom_allowlist:
            if pattern.fullmatch(cmd) is not None:
                return True
        return False
    return _default_command_allowed(arguments)


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
        raise HTTPException(
            status_code=502, detail=f"Failed to reach agent: {exc}"
        ) from exc

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

    if body.cwd and body.cwd.strip():
        raise HTTPException(
            status_code=403,
            detail="Working directory overrides are not allowed",
        )

    command = body.command.strip()
    try:
        arguments = shlex.split(command)
    except ValueError:
        arguments = []
    if not _command_allowed(command, arguments):
        raise HTTPException(
            status_code=403,
            detail="Command blocked by middleware allowlist / safety filter",
        )

    try:
        proc = await asyncio.create_subprocess_exec(
            *arguments,
            cwd=None,
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
