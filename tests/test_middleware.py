"""Edge middleware: forward signing, auth, and exec allowlist."""
from __future__ import annotations

import hashlib
import hmac
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
        expected = "sha256=" + hmac.new(
            b"agent-secret", captured["content"], hashlib.sha256
        ).hexdigest()
        assert sig == expected
        assert captured["headers"]["X-Org-ID"] == "acme"


class TestExec:
    def test_blocks_dangerous(self, client):
        res = client.post(
            "/exec",
            headers={"X-Middleware-Token": "mw-token"},
            json={"command": "rm -rf /"},
        )
        assert res.status_code == 403

    def test_allows_docker_ps(self, client):
        class FakeProc:
            returncode = 0

            async def communicate(self):
                return b"CONTAINER\n", b""

            def kill(self):
                return None

        async def fake_exec(*args, **kwargs):
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

    def test_exec_disabled(self, monkeypatch):
        monkeypatch.setenv("AGENT_BASE_URL", "https://agent.example.com")
        monkeypatch.setenv("MIDDLEWARE_AUTH_TOKEN", "")
        monkeypatch.setenv("MIDDLEWARE_EXEC_ENABLED", "false")
        client = TestClient(mw.app)
        res = client.post("/exec", json={"command": "docker ps"})
        assert res.status_code == 403
