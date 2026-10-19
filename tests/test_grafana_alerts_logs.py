"""Grafana alert intake, bearer auth for Alertmanager/Grafana, and Loki log retrieval."""
import json
import os
import time
from datetime import datetime, timezone

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest
from fastapi.testclient import TestClient

from api import server
from api.webhook_auth import bearer_token
from tools.observability import ObservabilityTools, default_log_provider, logql_selector

SECRET = "test-webhook-secret"

GRAFANA_PAYLOAD = {
    "receiver": "devops-agent",
    "status": "firing",
    "orgId": 1,
    "alerts": [
        {
            "status": "firing",
            "labels": {
                "alertname": "HighErrorRate",
                "namespace": "prod",
                "pod": "api-7d9f",
                "severity": "critical",
                "grafana_folder": "API",
            },
            "annotations": {
                "summary": "5xx rate above 5%",
                "description": "api is returning errors",
                "runbook_url": "https://runbooks.example.com/api-5xx",
            },
            "startsAt": "2026-10-19T10:00:00Z",
            "endsAt": "0001-01-01T00:00:00Z",
            "generatorURL": "https://grafana.example.com/alerting/grafana/abc/view",
            "dashboardURL": "https://grafana.example.com/d/api",
            "panelURL": "https://grafana.example.com/d/api?viewPanel=2",
            "values": {"B": 7.2},
        },
        {
            "status": "resolved",
            "labels": {"alertname": "DiskFull", "host": "web-1"},
            "annotations": {},
        },
    ],
}

ALERTMANAGER_PAYLOAD = {
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "PodCrashLooping", "namespace": "default"},
            "annotations": {"summary": "Pod is crash looping"},
        }
    ]
}


@pytest.fixture
def captured(monkeypatch):
    contexts = []

    async def fake_enqueue(context, incident_id=None):
        contexts.append(context)
        return f"INC-{len(contexts)}"

    monkeypatch.setattr(server, "enqueue_incident", fake_enqueue)
    return contexts


@pytest.fixture
def client(monkeypatch, captured):
    monkeypatch.setenv("WEBHOOK_SECRET", SECRET)
    return TestClient(server.app)


class TestBearerToken:
    @pytest.mark.parametrize(
        "header, expected",
        [
            ("Bearer abc", "abc"),
            ("bearer  abc ", "abc"),
            ("Basic abc", None),
            ("Bearer ", None),
            ("", None),
            (None, None),
        ],
    )
    def test_parse(self, header, expected):
        assert bearer_token(header) == expected


class TestAlertmanagerBearerAuth:
    def test_bearer_secret_accepted(self, client, captured):
        response = client.post(
            "/webhook/alertmanager",
            json=ALERTMANAGER_PAYLOAD,
            headers={"Authorization": f"Bearer {SECRET}"},
        )
        assert response.status_code == 200
        assert response.json()["incident_ids"] == ["INC-1"]
        assert captured[0]["source"] == "alertmanager"

    def test_wrong_bearer_rejected(self, client, captured):
        response = client.post(
            "/webhook/alertmanager",
            json=ALERTMANAGER_PAYLOAD,
            headers={"Authorization": "Bearer wrong"},
        )
        assert response.status_code == 401
        assert captured == []

    def test_basic_auth_with_secret_rejected(self, client, captured):
        response = client.post(
            "/webhook/alertmanager",
            json=ALERTMANAGER_PAYLOAD,
            headers={"Authorization": f"Basic {SECRET}"},
        )
        assert response.status_code == 401


class TestGrafanaWebhook:
    def test_firing_alerts_queued_with_grafana_fields(self, client, captured):
        response = client.post(
            "/webhook/grafana",
            json=GRAFANA_PAYLOAD,
            headers={"Authorization": f"Bearer {SECRET}"},
        )
        assert response.status_code == 200
        assert response.json() == {"status": "queued", "incident_ids": ["INC-1"]}

        context = captured[0]
        assert context["source"] == "grafana"
        assert context["alertname"] == "HighErrorRate"
        assert context["namespace"] == "prod"
        assert context["pod"] == "api-7d9f"
        assert context["severity"] == "critical"
        assert context["starts_at"] == "2026-10-19T10:00:00Z"
        assert context["dashboard_url"] == "https://grafana.example.com/d/api"
        assert context["panel_url"].endswith("viewPanel=2")
        assert context["runbook_url"] == "https://runbooks.example.com/api-5xx"
        assert context["alert_values"] == {"B": 7.2}

    def test_missing_auth_rejected(self, client, captured):
        response = client.post("/webhook/grafana", json=GRAFANA_PAYLOAD)
        assert response.status_code == 401
        assert captured == []

    def test_hmac_signature_still_accepted(self, client, captured):
        import hashlib
        import hmac

        body = json.dumps(GRAFANA_PAYLOAD).encode()
        sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
        response = client.post(
            "/webhook/grafana", content=body, headers={"X-Hub-Signature-256": sig}
        )
        assert response.status_code == 200

    def test_logql_annotation_carried(self, client, captured):
        payload = json.loads(json.dumps(GRAFANA_PAYLOAD))
        payload["alerts"][0]["annotations"]["logql"] = '{app="api"} |= "panic"'
        client.post(
            "/webhook/grafana", json=payload, headers={"Authorization": f"Bearer {SECRET}"}
        )
        assert captured[0]["logql"] == '{app="api"} |= "panic"'

    def test_x_org_id_header_sets_org(self, client, captured):
        client.post(
            "/webhook/grafana",
            json=GRAFANA_PAYLOAD,
            headers={"Authorization": f"Bearer {SECRET}", "X-Org-ID": "acme"},
        )
        assert captured[0]["org_id"] == "acme"


class FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, resp):
        self.resp = resp
        self.calls = []

    async def get(self, url, params=None, headers=None):
        self.calls.append({"url": url, "params": params, "headers": headers})
        return self.resp

    async def aclose(self):
        return None


def loki_streams(*streams):
    return {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {"stream": labels, "values": values} for labels, values in streams
            ],
        },
    }


@pytest.fixture
def grafana_loki(monkeypatch):
    monkeypatch.setenv("GRAFANA_URL", "https://grafana.example.com/")
    monkeypatch.setenv("GRAFANA_LOKI_DATASOURCE_UID", "loki-uid")
    monkeypatch.setenv("GRAFANA_TOKEN", "glsa_test")
    monkeypatch.delenv("LOKI_URL", raising=False)


class TestLogProvider:
    def test_none_configured(self, monkeypatch):
        for name in ("GRAFANA_URL", "GRAFANA_LOKI_DATASOURCE_UID", "LOKI_URL"):
            monkeypatch.delenv(name, raising=False)
        assert default_log_provider() is None

    def test_grafana_preferred(self, grafana_loki, monkeypatch):
        monkeypatch.setenv("LOKI_URL", "http://loki:3100")
        assert default_log_provider() == "grafana"

    def test_grafana_url_without_loki_uid_falls_back_to_loki(self, monkeypatch):
        monkeypatch.setenv("GRAFANA_URL", "https://grafana.example.com")
        monkeypatch.delenv("GRAFANA_LOKI_DATASOURCE_UID", raising=False)
        monkeypatch.setenv("LOKI_URL", "http://loki:3100")
        assert default_log_provider() == "loki"


class TestLogqlSelector:
    def test_namespace_and_pod(self):
        assert logql_selector({"namespace": "prod", "pod": "api-1", "job": "x"}) == (
            '{namespace="prod", pod="api-1"}'
        )

    def test_falls_back_to_job(self):
        assert logql_selector({"job": "node", "instance": "10.0.0.1:9100"}) == '{job="node"}'

    def test_no_usable_labels(self):
        assert logql_selector({"alertname": "X", "instance": "1.2.3.4"}) is None

    def test_values_are_escaped(self):
        selector = logql_selector({"app": 'a"} |= "x'})
        assert selector == '{app="a\\"} |= \\"x"}'


class TestQueryLogs:
    @pytest.mark.asyncio
    async def test_grafana_proxy_request_and_parsing(self, grafana_loki):
        resp = FakeResp(
            200,
            loki_streams(
                ({"app": "api"}, [["1760868000000000000", "older error"]]),
                ({"app": "worker"}, [["1760868060000000000", "newest panic"]]),
            ),
        )
        fake = FakeClient(resp)
        result = await ObservabilityTools(client=fake).query_logs('{app=~".+"}', limit=10)

        call = fake.calls[0]
        assert call["url"] == (
            "https://grafana.example.com/api/datasources/proxy/uid/loki-uid/loki/api/v1/query_range"
        )
        assert call["headers"] == {"Authorization": "Bearer glsa_test"}
        assert call["params"]["query"] == '{app=~".+"}'
        assert call["params"]["direction"] == "backward"
        assert call["params"]["limit"] == "10"
        # Loki takes nanosecond timestamps; default window is 30 minutes.
        window_ns = int(call["params"]["end"]) - int(call["params"]["start"])
        assert window_ns == pytest.approx(30 * 60 * 1e9, rel=1e-3)

        assert result["success"] is True
        assert result["provider"] == "grafana"
        assert result["line_count"] == 2
        assert [line["line"] for line in result["lines"]] == ["newest panic", "older error"]
        assert result["lines"][0]["labels"] == {"app": "worker"}
        assert result["lines"][0]["ts"].startswith("2025-10-19T")

    @pytest.mark.asyncio
    async def test_direct_loki(self, monkeypatch):
        monkeypatch.delenv("GRAFANA_LOKI_DATASOURCE_UID", raising=False)
        monkeypatch.setenv("LOKI_URL", "http://loki:3100/")
        monkeypatch.setenv("LOKI_TOKEN", "loki-token")
        fake = FakeClient(FakeResp(200, loki_streams()))
        result = await ObservabilityTools(client=fake).query_logs('{job="x"}')
        assert fake.calls[0]["url"] == "http://loki:3100/loki/api/v1/query_range"
        assert fake.calls[0]["headers"] == {"Authorization": "Bearer loki-token"}
        assert result == {
            "success": True,
            "provider": "loki",
            "query": '{job="x"}',
            "line_count": 0,
            "lines": [],
        }

    @pytest.mark.asyncio
    async def test_not_configured(self, monkeypatch):
        for name in ("GRAFANA_URL", "GRAFANA_LOKI_DATASOURCE_UID", "LOKI_URL"):
            monkeypatch.delenv(name, raising=False)
        result = await ObservabilityTools(client=FakeClient(None)).query_logs('{job="x"}')
        assert "No log provider configured" in result["error"]

    @pytest.mark.asyncio
    async def test_http_error_returned(self, grafana_loki):
        fake = FakeClient(FakeResp(403, {"message": "forbidden"}))
        result = await ObservabilityTools(client=fake).query_logs('{job="x"}')
        assert result["error"].startswith("403 from")

    @pytest.mark.asyncio
    async def test_limit_clamped_and_long_lines_truncated(self, grafana_loki):
        fake = FakeClient(
            FakeResp(200, loki_streams(({"app": "a"}, [["1760868000000000000", "x" * 5000]])))
        )
        result = await ObservabilityTools(client=fake).query_logs('{app="a"}', limit=50000)
        assert fake.calls[0]["params"]["limit"] == "1000"
        assert len(result["lines"][0]["line"]) == 2000


class TestLogsForAlert:
    @pytest.mark.asyncio
    async def test_builds_error_query_from_labels(self, grafana_loki):
        fake = FakeClient(FakeResp(200, loki_streams()))
        starts_at = datetime.now(timezone.utc).replace(microsecond=0)
        context = {
            "namespace": "prod",
            "pod": "api-1",
            "labels": {"alertname": "HighErrorRate"},
            "starts_at": starts_at.isoformat().replace("+00:00", "Z"),
        }
        result = await ObservabilityTools(client=fake).logs_for_alert(context)
        assert result["success"] is True
        params = fake.calls[0]["params"]
        assert params["query"].startswith('{namespace="prod", pod="api-1"} |~ "(?i)(error')
        # Window starts 15 minutes before the alert fired.
        assert int(params["start"]) / 1e9 == pytest.approx(starts_at.timestamp() - 900, abs=1)

    @pytest.mark.asyncio
    async def test_old_alert_window_capped_to_one_day(self, grafana_loki):
        fake = FakeClient(FakeResp(200, loki_streams()))
        context = {"labels": {"job": "api"}, "starts_at": "2020-01-01T00:00:00Z"}
        await ObservabilityTools(client=fake).logs_for_alert(context)
        start = int(fake.calls[0]["params"]["start"]) / 1e9
        assert start == pytest.approx(time.time() - 24 * 3600, abs=5)

    @pytest.mark.asyncio
    async def test_logql_annotation_used_verbatim(self, grafana_loki):
        fake = FakeClient(FakeResp(200, loki_streams()))
        await ObservabilityTools(client=fake).logs_for_alert(
            {"logql": '{app="api"} |= "panic"', "labels": {"namespace": "prod", "pod": "p"}}
        )
        assert fake.calls[0]["params"]["query"] == '{app="api"} |= "panic"'

    @pytest.mark.asyncio
    async def test_none_without_provider_or_selector(self, grafana_loki, monkeypatch):
        fake = FakeClient(FakeResp(200, loki_streams()))
        tools = ObservabilityTools(client=fake)
        assert await tools.logs_for_alert({"labels": {"alertname": "X"}}) is None
        monkeypatch.delenv("GRAFANA_LOKI_DATASOURCE_UID")
        assert await tools.logs_for_alert({"labels": {"job": "api"}}) is None
        assert fake.calls == []


class TestAgentEnrichment:
    @pytest.mark.asyncio
    async def test_grafana_incident_gets_alert_logs(self, grafana_loki, monkeypatch):
        from agent.core import DevOpsAgent

        agent = DevOpsAgent()
        logs = {"success": True, "lines": [{"line": "panic: nil map"}]}

        async def fake_logs(context, limit=100):
            assert context["source"] == "grafana"
            return logs

        monkeypatch.setattr(agent.observability, "logs_for_alert", fake_logs)
        enriched = await agent._collect_context(
            {"type": "observability", "source": "grafana", "labels": {"job": "api"}}
        )
        assert enriched["alert_logs"] == logs

    @pytest.mark.asyncio
    async def test_log_failure_does_not_block(self, grafana_loki, monkeypatch):
        from agent.core import DevOpsAgent

        agent = DevOpsAgent()

        async def boom(context, limit=100):
            raise RuntimeError("loki down")

        monkeypatch.setattr(agent.observability, "logs_for_alert", boom)
        enriched = await agent._collect_context(
            {"type": "observability", "source": "alertmanager", "labels": {}}
        )
        assert "alert_logs" not in enriched

    @pytest.mark.asyncio
    async def test_query_logs_tool_dispatch(self, grafana_loki, monkeypatch):
        from agent.core import AGENT_TOOLS, DevOpsAgent

        assert any(tool["name"] == "query_logs" for tool in AGENT_TOOLS)
        agent = DevOpsAgent()
        seen = {}

        async def fake_query_logs(query, provider=None, since_minutes=30, limit=200):
            seen.update(query=query, provider=provider, since=since_minutes, limit=limit)
            return {"success": True, "lines": []}

        monkeypatch.setattr(agent.observability, "query_logs", fake_query_logs)
        result = await agent._execute_tool(
            "query_logs", {"query": '{app="api"}', "since_minutes": 60}, {}
        )
        assert result["success"] is True
        assert seen == {"query": '{app="api"}', "provider": None, "since": 60, "limit": 200}

    def test_prompt_mentions_logs_only_when_configured(self, grafana_loki, monkeypatch):
        from agent.prompts import get_system_prompt

        assert "query_logs (LogQL)" in get_system_prompt("k8s")
        monkeypatch.delenv("GRAFANA_LOKI_DATASOURCE_UID")
        assert "query_logs (LogQL)" not in get_system_prompt("k8s")
