"""Credential entry points must restore cached clients as well as the environment."""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

from agent.core import DevOpsAgent
from devops_mcp.registry import _make_agent_tool_handler, register_platform_tools
from services.escalation import EscalationService
from services.org_config import OrgConfig
from services.org_context import org_credentials
from storage.memory_storage import MemoryStorage
from tools.notify import SlackNotifier


@pytest.fixture
def credential_config(monkeypatch):
    monkeypatch.setenv("ORG_ID", "default")
    monkeypatch.setenv("GITLAB_TOKEN", "default-gitlab")
    monkeypatch.setenv("PAGERDUTY_TOKEN", "default-pagerduty")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy-test-key")
    config = OrgConfig(storage=MemoryStorage())
    for org in ("org-a", "org-b"):
        config.save(
            org,
            {
                "GITLAB_TOKEN": f"{org}-gitlab",
                "PAGERDUTY_TOKEN": f"{org}-pagerduty",
            },
        )
    monkeypatch.setattr("services.org_context.OrgConfig", lambda: config)
    return config


@pytest.fixture
def agent(credential_config):
    return DevOpsAgent()


def assert_org_credentials(agent, org):
    assert os.environ["GITLAB_TOKEN"] == f"{org}-gitlab"
    assert agent.gitlab_collector.token == f"{org}-gitlab"


async def call_with_outcome(callback, outcome):
    if outcome is None:
        await callback()
    else:
        with pytest.raises(outcome):
            await callback()


@pytest.mark.asyncio
@pytest.mark.parametrize("entry_point", ["run", "execute_tool"])
@pytest.mark.parametrize("outcome", [None, RuntimeError, asyncio.CancelledError])
async def test_agent_entry_points_restore_clients(
    agent, monkeypatch, entry_point, outcome
):
    async def operation(*args):
        assert_org_credentials(agent, "org-a")
        if outcome:
            raise outcome()
        return {"ok": True}

    if entry_point == "run":
        monkeypatch.setattr(agent, "_run_with_org_context", operation)
        callback = lambda: agent.run({"org_id": "org-a"}, "INC-1")
    else:
        monkeypatch.setattr(agent, "_execute_tool", operation)
        callback = lambda: agent.execute_tool(
            "get_gitlab_pipeline", {}, {"org_id": "org-a"}
        )

    await call_with_outcome(callback, outcome)
    assert_org_credentials(agent, "default")


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", [None, RuntimeError, asyncio.CancelledError])
async def test_mcp_tool_handler_applies_and_restores_org(agent, monkeypatch, outcome):
    async def execute_tool(name, inputs, context):
        assert context == {"org_id": "org-b"}
        assert_org_credentials(agent, "org-b")
        if outcome:
            raise outcome()
        return {"ok": True}

    # Verify the MCP boundary itself, independently of DevOpsAgent.execute_tool.
    monkeypatch.setattr(agent, "execute_tool", execute_tool)
    handler = _make_agent_tool_handler(agent, "get_gitlab_pipeline", {"properties": {}})
    await call_with_outcome(lambda: handler(org_id="org-b"), outcome)
    assert_org_credentials(agent, "default")


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", [None, RuntimeError, asyncio.CancelledError])
async def test_mcp_diagnosis_restores_clients(
    agent, credential_config, monkeypatch, outcome
):
    handlers = {}
    mcp = MagicMock()
    mcp.tool.side_effect = lambda **kwargs: lambda fn: handlers.setdefault(
        kwargs["name"], fn
    )
    register_platform_tools(
        mcp, agent, MagicMock(), MagicMock(), MagicMock(), credential_config
    )

    async def run(*args, **kwargs):
        assert_org_credentials(agent, "org-a")
        if outcome:
            raise outcome()
        return {"ok": True}

    monkeypatch.setattr(agent, "run", run)
    await call_with_outcome(
        lambda: handlers["diagnose_incident"]("cicd", org_id="org-a"), outcome
    )
    assert_org_credentials(agent, "default")


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", [None, RuntimeError, asyncio.CancelledError])
async def test_queued_incident_restores_agent_and_escalation(
    agent, monkeypatch, outcome
):
    from api import server

    escalation = EscalationService()
    monkeypatch.setattr(server, "agent", agent)
    monkeypatch.setattr(server, "escalation_service", escalation)

    async def process(*args):
        assert_org_credentials(agent, "org-a")
        assert escalation.pagerduty.token == "org-a-pagerduty"
        if outcome:
            raise outcome()

    monkeypatch.setattr(server, "_process_incident_with_org_creds", process)
    await call_with_outcome(
        lambda: server.process_incident({"incident_id": "INC-1", "org_id": "org-a"}),
        outcome,
    )
    assert_org_credentials(agent, "default")
    assert escalation.pagerduty.token == "default-pagerduty"


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", [None, RuntimeError, asyncio.CancelledError])
async def test_approved_action_applies_and_restores_org(agent, monkeypatch, outcome):
    async def execute(command):
        assert command == "kubectl get pods"
        assert_org_credentials(agent, "org-b")
        if outcome:
            raise outcome()
        return {"stdout": "pods"}

    monkeypatch.setattr(agent.executor, "run", execute)
    monkeypatch.setattr(agent.notifier, "send_message", AsyncMock())
    await call_with_outcome(
        lambda: agent.execute_approved_action(
            "INC-1", "kubectl get pods", org_id="org-b"
        ),
        outcome,
    )
    assert_org_credentials(agent, "default")


def post_slack_approval(server, monkeypatch, value):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "test-slack-signing-secret")
    body = urlencode(
        {
            "payload": json.dumps(
                {
                    "actions": [
                        {
                            "action_id": "approve_action",
                            "value": value,
                        }
                    ]
                }
            )
        }
    ).encode()
    timestamp = str(int(time.time()))
    digest = hmac.new(
        b"test-slack-signing-secret",
        b"v0:" + timestamp.encode() + b":" + body,
        hashlib.sha256,
    ).hexdigest()
    return TestClient(server.app).post(
        "/slack/action",
        content=body,
        headers={
            "X-Slack-Request-Timestamp": timestamp,
            "X-Slack-Signature": f"v0={digest}",
        },
    )


@pytest.mark.asyncio
async def test_slack_approval_keeps_org_through_background_execution(
    agent,
    credential_config,
    monkeypatch,
):
    from api import server

    http = AsyncMock()
    http.post.return_value = MagicMock(status_code=200)
    factory = MagicMock()
    factory.return_value.__aenter__ = AsyncMock(return_value=http)
    factory.return_value.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr("tools.notify.httpx.AsyncClient", factory)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://slack.invalid/test")

    with org_credentials("org-a", credential_config):
        await SlackNotifier().send_message(
            "Approval needed",
            requires_approval=True,
            approval_command="kubectl get pods",
        )
    blocks = http.post.call_args.kwargs["json"]["blocks"]
    value = next(b for b in blocks if b["type"] == "actions")["elements"][0]["value"]
    assert json.loads(value)["org_id"] == "org-a"

    observed = []

    async def execute(command):
        assert_org_credentials(agent, "org-a")
        observed.append(command)
        return {"stdout": "pods"}

    monkeypatch.setattr(server, "agent", agent)
    monkeypatch.setattr(agent.executor, "run", execute)
    monkeypatch.setattr(agent.notifier, "send_message", AsyncMock())
    response = post_slack_approval(server, monkeypatch, value)
    assert response.status_code == 200
    assert observed == ["kubectl get pods"]
    assert_org_credentials(agent, "default")


@pytest.mark.parametrize(
    "approval",
    [
        "legacy",
        {"incident_id": "INC-1", "command": "a3ViZWN0bCBnZXQgcG9kcw=="},
        {"org_id": "", "incident_id": "INC-1", "command": "a3ViZWN0bCBnZXQgcG9kcw=="},
        {"org_id": 123, "incident_id": "INC-1", "command": "a3ViZWN0bCBnZXQgcG9kcw=="},
        {"org_id": "org-a", "incident_id": "INC-1", "command": "not base64!"},
        {"org_id": "org-a", "incident_id": "INC-1", "command": ""},
    ],
)
def test_slack_rejects_approval_without_valid_context(agent, monkeypatch, approval):
    from api import server

    monkeypatch.setattr(server, "agent", agent)
    execute = AsyncMock()
    monkeypatch.setattr(agent, "execute_approved_action", execute)
    if approval == "legacy":
        encoded = base64.b64encode(b"kubectl get pods").decode()
        value = f"PENDING:{encoded}"
    else:
        value = json.dumps(approval)
    response = post_slack_approval(server, monkeypatch, value)
    assert response.status_code == 400
    execute.assert_not_called()


@pytest.mark.asyncio
async def test_nested_agent_calls_restore_enclosing_org(agent, monkeypatch):
    from services.org_context import current_org_id

    async def execute(*args):
        assert_org_credentials(agent, "org-b")
        assert current_org_id() == "org-b"
        return {"ok": True}

    async def run(*args):
        assert_org_credentials(agent, "org-a")
        await agent.execute_tool("get_gitlab_pipeline", {}, {"org_id": "org-b"})
        assert_org_credentials(agent, "org-a")
        assert current_org_id() == "org-a"
        return {"ok": True}

    monkeypatch.setattr(agent, "_execute_tool", execute)
    monkeypatch.setattr(agent, "_run_with_org_context", run)
    await agent.run({"org_id": "org-a"}, "INC-1")
    assert_org_credentials(agent, "default")
    assert current_org_id() == "default"


@pytest.mark.asyncio
async def test_org_token_is_removed_when_default_has_no_token(agent, monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN")
    agent.gitlab_collector.refresh_credentials()

    async def execute(*args):
        assert_org_credentials(agent, "org-a")
        return {"ok": True}

    monkeypatch.setattr(agent, "_execute_tool", execute)
    await agent.execute_tool("get_gitlab_pipeline", {}, {"org_id": "org-a"})
    assert "GITLAB_TOKEN" not in os.environ
    assert agent.gitlab_collector.token == ""
