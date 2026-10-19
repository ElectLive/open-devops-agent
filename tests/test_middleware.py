"""Edge middleware: forward signing, auth, and exec allowlist."""

from __future__ import annotations

import hashlib
import hmac
import shlex
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "middleware"))

import app as mw  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AGENT_BASE_URL", "https://agent.example.com")
    monkeypatch.setenv("AGENT_WEBHOOK_SECRET", "agent-secret")
    monkeypatch.setenv("MIDDLEWARE_AUTH_TOKEN", "mw-token")
    monkeypatch.setenv("ORG_ID", "acme")
    monkeypatch.setenv("MIDDLEWARE_EXEC_ENABLED", "true")
    monkeypatch.delenv("MIDDLEWARE_DEFAULT_HOST", raising=False)
    monkeypatch.delenv("MIDDLEWARE_EXEC_ALLOWLIST", raising=False)
    return TestClient(mw.app)


class TestMiddlewareHealth:
    def test_health(self, client):
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json()["agent_configured"] is True
        assert res.json()["exec_enabled"] is True


class TestForward:
    def test_requires_auth(self, client):
        res = client.post("/forward", json={"type": "server", "description": "x"})
        assert res.status_code == 401

    def test_forwards_with_signature(self, client):
        captured = {}

        async def fake_post(url, content=None, headers=None):
            captured["url"] = url
            captured["content"] = content
            captured["headers"] = headers
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"status": "queued", "incident_id": "abc"}
            resp.text = ""
            return resp

        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=fake_post)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch.object(mw.httpx, "AsyncClient", return_value=mock_client):
            res = client.post(
                "/forward",
                headers={"Authorization": "Bearer mw-token"},
                json={"type": "server", "description": "disk full"},
            )

        assert res.status_code == 200
        body = res.json()
        assert body["status"] == "forwarded"
        assert captured["url"] == "https://agent.example.com/webhook/manual"
        sig = captured["headers"]["X-Hub-Signature-256"]
        expected = (
            "sha256="
            + hmac.new(b"agent-secret", captured["content"], hashlib.sha256).hexdigest()
        )
        assert sig == expected
        assert captured["headers"]["X-Org-ID"] == "acme"

    def test_token_unset_rejects(self, monkeypatch):
        monkeypatch.setenv("AGENT_BASE_URL", "https://agent.example.com")
        monkeypatch.delenv("MIDDLEWARE_AUTH_TOKEN", raising=False)
        monkeypatch.delenv("MIDDLEWARE_ALLOW_UNAUTHENTICATED", raising=False)
        client = TestClient(mw.app)
        res = client.post("/forward", json={"type": "server", "description": "x"})
        assert res.status_code == 401
        assert res.json()["detail"] == "Middleware auth token required"

    def test_allow_unauthenticated_forward_works(self, monkeypatch):
        monkeypatch.setenv("AGENT_BASE_URL", "https://agent.example.com")
        monkeypatch.setenv("AGENT_WEBHOOK_SECRET", "agent-secret")
        monkeypatch.delenv("MIDDLEWARE_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("MIDDLEWARE_ALLOW_UNAUTHENTICATED", "true")
        client = TestClient(mw.app)

        captured = {}

        async def fake_post(url, content=None, headers=None):
            captured["url"] = url
            captured["content"] = content
            captured["headers"] = headers
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"status": "queued", "incident_id": "abc"}
            resp.text = ""
            return resp

        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=fake_post)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch.object(mw.httpx, "AsyncClient", return_value=mock_client):
            res = client.post(
                "/forward",
                json={"type": "server", "description": "disk full"},
            )

        assert res.status_code == 200
        assert res.json()["status"] == "forwarded"

    def test_caller_org_id_ignored_by_default(self, client):
        captured = {}

        async def fake_post(url, content=None, headers=None):
            captured["headers"] = headers
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"status": "queued"}
            resp.text = ""
            return resp

        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=fake_post)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch.object(mw.httpx, "AsyncClient", return_value=mock_client):
            res = client.post(
                "/forward",
                headers={
                    "Authorization": "Bearer mw-token",
                    "X-Org-ID": "spoofed-org",
                },
                json={
                    "type": "server",
                    "description": "x",
                    "org_id": "spoofed-body-org",
                },
            )

        assert res.status_code == 200
        assert captured["headers"]["X-Org-ID"] == "acme"
        assert res.json()["org_id"] == "acme"

    def test_caller_org_id_trusted_when_flag_enabled(self, client, monkeypatch):
        monkeypatch.setenv("MIDDLEWARE_TRUST_CALLER_ORG_ID", "true")
        captured = {}

        async def fake_post(url, content=None, headers=None):
            captured["headers"] = headers
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"status": "queued"}
            resp.text = ""
            return resp

        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=fake_post)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch.object(mw.httpx, "AsyncClient", return_value=mock_client):
            res = client.post(
                "/forward",
                headers={
                    "Authorization": "Bearer mw-token",
                    "X-Org-ID": "trusted-tenant",
                },
                json={"type": "server", "description": "x"},
            )

        assert res.status_code == 200
        assert captured["headers"]["X-Org-ID"] == "trusted-tenant"
        assert res.json()["org_id"] == "trusted-tenant"

    def test_caller_org_id_allowlist(self, client, monkeypatch):
        monkeypatch.setenv("MIDDLEWARE_TRUST_CALLER_ORG_ID", "tenant-a,tenant-b")
        captured = {}

        async def fake_post(url, content=None, headers=None):
            captured["headers"] = headers
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"status": "queued"}
            resp.text = ""
            return resp

        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=fake_post)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch.object(mw.httpx, "AsyncClient", return_value=mock_client):
            # Allowed tenant in allowlist
            res1 = client.post(
                "/forward",
                headers={
                    "Authorization": "Bearer mw-token",
                    "X-Org-ID": "tenant-a",
                },
                json={"type": "server", "description": "x"},
            )
            assert res1.status_code == 200
            assert captured["headers"]["X-Org-ID"] == "tenant-a"
            assert res1.json()["org_id"] == "tenant-a"

            # Disallowed tenant falls back to configured ORG_ID
            res2 = client.post(
                "/forward",
                headers={
                    "Authorization": "Bearer mw-token",
                    "X-Org-ID": "unlisted-tenant",
                },
                json={"type": "server", "description": "x"},
            )
            assert res2.status_code == 200
            assert captured["headers"]["X-Org-ID"] == "acme"
            assert res2.json()["org_id"] == "acme"


class TestExec:
    def test_blocks_dangerous(self, client):
        res = client.post(
            "/exec",
            headers={"X-Middleware-Token": "mw-token"},
            json={"command": "rm -rf /"},
        )
        assert res.status_code == 403

    def test_allows_docker_ps(self, client):
        proc_call = {}

        class FakeProc:
            returncode = 0

            async def communicate(self):
                return b"CONTAINER\n", b""

            def kill(self):
                return None

        async def fake_exec(*args, **kwargs):
            proc_call["args"] = args
            proc_call["cwd"] = kwargs.get("cwd")
            return FakeProc()

        with patch.object(mw.asyncio, "create_subprocess_exec", side_effect=fake_exec):
            res = client.post(
                "/exec",
                headers={"Authorization": "Bearer mw-token"},
                json={"command": "docker ps"},
            )

        assert res.status_code == 200
        assert res.json()["success"] is True
        assert "CONTAINER" in res.json()["stdout"]
        assert proc_call == {"args": ("docker", "ps"), "cwd": None}

    def test_exec_disabled(self, monkeypatch):
        monkeypatch.setenv("AGENT_BASE_URL", "https://agent.example.com")
        monkeypatch.setenv("MIDDLEWARE_AUTH_TOKEN", "")
        monkeypatch.setenv("MIDDLEWARE_EXEC_ENABLED", "false")
        client = TestClient(mw.app)
        res = client.post("/exec", json={"command": "docker ps"})
        assert res.status_code == 403

    def test_exec_refuses_when_token_unset(self, monkeypatch):
        monkeypatch.setenv("AGENT_BASE_URL", "https://agent.example.com")
        monkeypatch.delenv("MIDDLEWARE_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("MIDDLEWARE_EXEC_ENABLED", "true")
        client = TestClient(mw.app)
        res = client.post("/exec", json={"command": "docker ps"})
        assert res.status_code == 503
        assert res.json()["detail"] == "MIDDLEWARE_AUTH_TOKEN required for exec"

    def test_exec_refuses_without_token_even_with_allow_unauthenticated(
        self, monkeypatch
    ):
        monkeypatch.setenv("AGENT_BASE_URL", "https://agent.example.com")
        monkeypatch.delenv("MIDDLEWARE_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("MIDDLEWARE_EXEC_ENABLED", "true")
        monkeypatch.setenv("MIDDLEWARE_ALLOW_UNAUTHENTICATED", "true")
        client = TestClient(mw.app)
        res = client.post("/exec", json={"command": "docker ps"})
        assert res.status_code == 503
        assert res.json()["detail"] == "MIDDLEWARE_AUTH_TOKEN required for exec"

    def test_exec_rejects_invalid_token(self, client):
        res = client.post(
            "/exec",
            headers={"Authorization": "Bearer wrong-token"},
            json={"command": "docker ps"},
        )
        assert res.status_code == 401
        assert res.json()["detail"] == "Invalid middleware token"
