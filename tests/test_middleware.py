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
        expected_digest = hmac.new(
            b"agent-secret", captured["content"], hashlib.sha256
        ).hexdigest()
        expected = "sha256=" + expected_digest
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

    @pytest.mark.parametrize(
        "command",
        [
            "journalctl --vacuum-time=1s",
            "kubectl get secrets -A -o yaml",
            "kubectl get sec -A",
            "kubectl describe secret app-secret",
            "kubectl rollout undo deploy/api",
            "kubectl rollout restart deploy/api",
            "docker inspect api",
            "docker restart api",
            "systemctl restart nginx",
            "systemctl reload docker",
            "kubectl get pods --kubeconfig=/root/.kube/other",
            "kubectl --kubeconfig /root/.kube/other get pods",
            "kubectl --server=https://other.example get pods",
            "kubectl --as-uid=0 get pods",
            "kubectl get pods --token secret",
            "docker ps --host=tcp://other.example",
            "docker -H tcp://other.example ps",
            "docker ps; whoami",
            "kubectl get pods\nwhoami",
            'docker "ps',
        ],
    )
    def test_blocks_dangerous_arguments(self, client, command):
        exec_process = patch.object(mw.asyncio, "create_subprocess_exec")
        with exec_process as mocked_exec:
            res = client.post(
                "/exec",
                headers={"X-Middleware-Token": "mw-token"},
                json={"command": command},
            )

        assert res.status_code == 403
        mocked_exec.assert_not_called()

    @pytest.mark.parametrize(
        "command",
        [
            "docker ps",
            "docker ps --all --no-trunc",
            "docker logs api --tail 100",
            "systemctl status nginx",
            "systemctl status --no-pager docker",
            "nginx -t",
            "df -h",
            'journalctl -u nginx.service --since "1 hour ago" --no-pager',
            "journalctl --lines=100",
            "kubectl get pods",
            "kubectl get pods -n default -o wide",
            "kubectl get all -A",
            "kubectl describe node worker-1",
            "kubectl logs pod/api --tail=100 -n default --timestamps",
            "kubectl rollout status deploy/api -n default --watch=false",
        ],
    )
    def test_allows_supported_read_only_arguments(self, command, monkeypatch):
        monkeypatch.delenv("MIDDLEWARE_EXEC_ALLOWLIST", raising=False)
        assert mw._command_allowed(command, shlex.split(command))

    def test_custom_allowlist_requires_full_command_match(self, monkeypatch):
        monkeypatch.setenv("MIDDLEWARE_EXEC_ALLOWLIST", r"^echo\s+safe$")

        assert mw._command_allowed("echo safe", ["echo", "safe"])
        command = "echo safe extra"
        arguments = ["echo", "safe", "extra"]
        assert not mw._command_allowed(command, arguments)

    def test_invalid_custom_allowlist_fails_closed(self, monkeypatch):
        monkeypatch.setenv("MIDDLEWARE_EXEC_ALLOWLIST", "[")

        assert not mw._command_allowed("docker ps", ["docker", "ps"])

    def test_rejects_caller_working_directory(self, client):
        exec_process = patch.object(mw.asyncio, "create_subprocess_exec")
        with exec_process as mocked_exec:
            res = client.post(
                "/exec",
                headers={"X-Middleware-Token": "mw-token"},
                json={"command": "docker ps", "cwd": "C:\\Users\\Public"},
            )

        assert res.status_code == 403
        mocked_exec.assert_not_called()
