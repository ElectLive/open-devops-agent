"""apply_k8s_manifest must not reach the cluster before approval (#102)."""
import base64
import subprocess
from unittest.mock import AsyncMock

import pytest

from storage.memory_storage import MemoryStorage
from tools.k8s_tools import K8sTools

MANIFEST = """apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  quote: "it's $(not) `expanded`; | & >"
"""


@pytest.fixture
def tools(monkeypatch):
    monkeypatch.delenv("AGENT_EMERGENCY_STOP", raising=False)
    storage = MemoryStorage()
    monkeypatch.setattr("storage.factory.get_storage", lambda: storage)
    instance = K8sTools()
    calls = []
    outcome = {"success": True, "stdout": "configmap/app-config configured (dry run)", "stderr": ""}

    async def record(command, host=None):
        calls.append(command)
        return dict(outcome, command=command)

    monkeypatch.setattr(instance.executor, "_exec", record)
    return instance, calls, outcome


def is_dry_run(command):
    return command.endswith("--dry-run=client")


@pytest.mark.asyncio
async def test_live_apply_without_auto_apply_only_dry_runs(tools):
    k8s, calls, _ = tools
    notifier = AsyncMock()

    result = await k8s.apply_manifest(
        MANIFEST, dry_run=False, namespace="default", auto_apply=False, notifier=notifier
    )

    assert len(calls) == 1
    assert calls[0].startswith("kubectl apply -f ")
    assert is_dry_run(calls[0])
    assert result["requires_approval"] is True
    assert result["blocked"] is True
    assert "nothing was applied" in result["message"]
    assert result["command"].startswith("agent-approval:")
    assert base64.b64decode(result["approval_payload"]).decode() == result["command"]
    notifier.send_approval_request.assert_awaited_once()
    assert notifier.send_approval_request.await_args.args[1] == result["command"]


@pytest.mark.asyncio
async def test_approved_reference_applies_the_manifest_once(tools):
    k8s, calls, _ = tools
    result = await k8s.apply_manifest(
        MANIFEST, dry_run=False, namespace="default", auto_apply=False
    )
    calls.clear()

    approved = await k8s.executor.run(result["command"])

    assert approved["success"] is True
    assert len(calls) == 1
    live = calls[0]
    assert not is_dry_run(live)
    assert live.endswith("| kubectl apply -f - -n default")
    # The approved command carries the manifest, not the deleted temp file.
    assert ".yaml" not in live

    replay = await k8s.executor.run(result["command"])
    assert replay["blocked"] is True
    assert len(calls) == 1


def test_approved_command_decodes_manifest_verbatim_in_a_shell(tools):
    """Swap kubectl for cat and run the real pipeline: the YAML must arrive unchanged."""
    import asyncio

    k8s, calls, _ = tools
    result = asyncio.run(
        k8s.apply_manifest(MANIFEST, dry_run=False, namespace="default", auto_apply=False)
    )
    calls.clear()
    asyncio.run(k8s.executor.run(result["command"]))
    pipeline = calls[0].replace("kubectl apply -f - -n default", "cat")

    out = subprocess.run(["sh", "-c", pipeline], capture_output=True, text=True, check=True)
    assert out.stdout == MANIFEST


@pytest.mark.asyncio
async def test_failed_validation_requests_no_approval(tools):
    k8s, calls, outcome = tools
    outcome.update(success=False, stdout="", stderr="error: unknown field \"spec.bogus\"")
    notifier = AsyncMock()

    result = await k8s.apply_manifest(
        MANIFEST, dry_run=False, namespace="default", auto_apply=False, notifier=notifier
    )

    assert len(calls) == 1 and is_dry_run(calls[0])
    assert result["success"] is False
    assert "requires_approval" not in result
    assert "spec.bogus" in result["dry_run_error"]
    notifier.send_approval_request.assert_not_awaited()


@pytest.mark.asyncio
async def test_dry_run_only_validates(tools):
    k8s, calls, _ = tools
    result = await k8s.apply_manifest(MANIFEST, dry_run=True, namespace="default")
    assert len(calls) == 1 and is_dry_run(calls[0])
    assert result["success"] is True
    assert "requires_approval" not in result


@pytest.mark.asyncio
async def test_auto_apply_applies_directly(tools):
    k8s, calls, _ = tools
    notifier = AsyncMock()
    await k8s.apply_manifest(
        MANIFEST, dry_run=False, namespace="default", auto_apply=True, notifier=notifier
    )
    assert len(calls) == 1
    assert not is_dry_run(calls[0])
    assert calls[0].startswith("kubectl apply -f ") and calls[0].endswith(" -n default")
    notifier.send_approval_request.assert_not_awaited()


@pytest.mark.asyncio
async def test_disallowed_namespace_runs_nothing(tools):
    k8s, calls, _ = tools
    result = await k8s.apply_manifest(MANIFEST, dry_run=False, namespace="kube-system")
    assert result["blocked"] is True
    assert calls == []
