"""Agent-level approval and emergency-stop boundaries for host operations."""

import ast
import asyncio
import base64
import importlib
import inspect
import json
import runpy
import shlex
import textwrap

import pytest

from agent.core import AGENT_TOOLS, DevOpsAgent
from tools.disk_cleanup import DiskCleanup
from tools.executor import SafeExecutor
from tools.nginx_tools import NginxTools
from tools.safety import MUTATING_AGENT_TOOLS
from tools.security_updates import SecurityUpdates

HOST_TOOL_TYPES = {
    "disk_cleanup": DiskCleanup,
    "nginx_tools": NginxTools,
    "security_updates": SecurityUpdates,
}
SCHEMAS = {tool["name"]: tool["input_schema"] for tool in AGENT_TOOLS}


def dispatched_tools():
    """Enumerate literal name branches and their directly referenced handlers."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(DevOpsAgent._execute_tool)))
    dispatch = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        test = node.test
        if not (
            isinstance(test.left, ast.Name)
            and test.left.id == "name"
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and isinstance(test.comparators[0], ast.Constant)
        ):
            continue
        dispatch[test.comparators[0].value] = {
            ref.attr
            for statement in node.body
            for ref in ast.walk(statement)
            if isinstance(ref, ast.Attribute)
            and isinstance(ref.value, ast.Name)
            and ref.value.id == "self"
        }
    return dispatch


DISPATCH = dispatched_tools()
HOST_MUTATIONS = sorted(
    name
    for name, handlers in DISPATCH.items()
    if name in MUTATING_AGENT_TOOLS and handlers & HOST_TOOL_TYPES.keys()
)
DRY_RUN_MUTATIONS = [
    name for name in HOST_MUTATIONS if "dry_run" in SCHEMAS[name]["properties"]
]

# Every new dispatch must be reviewed as mutating or explicitly exempted here.
# restore_from_snapshot always refuses execution; commander selection only reads
# the roster. Notifications and suggestions are deliberately available in a stop.
NON_MUTATING_DISPATCH = {
    "get_k8s_context",
    "get_github_logs",
    "get_cicd_logs",
    "get_argocd_status",
    "get_argocd_history",
    "get_helm_release",
    "terraform_validate",
    "terraform_plan",
    "get_cloud_resource",
    "inspect_disk_usage",
    "diagnose_nginx",
    "bamboo_check_version",
    "query_metrics",
    "evaluate_slo",
    "capacity_check",
    "query_traces",
    "query_logs",
    "run_synthetic",
    "get_oncall_roster",
    "assign_incident_commander",
    "check_database_health",
    "list_snapshots",
    "restore_from_snapshot",
    "dr_readiness_check",
    "kafka_health",
    "elasticsearch_health",
    "redis_health",
    "fetch_code_change",
    "list_open_code_changes",
    "suggest_fix",
    "notify_slack",
}


def test_mutating_safety_set_reconciles_with_agent_dispatch_and_registration():
    assert set(DISPATCH) == set(SCHEMAS)
    assert not NON_MUTATING_DISPATCH & MUTATING_AGENT_TOOLS
    assert set(DISPATCH) - NON_MUTATING_DISPATCH == MUTATING_AGENT_TOOLS & set(DISPATCH)
    assert HOST_MUTATIONS
    assert DRY_RUN_MUTATIONS


class RecordingRunner:
    def __init__(self):
        self.calls = []
        self.allow_mutations = False
        self.forbid_all = False

    async def __call__(self, command, host):
        self.calls.append((command, host))
        read_only = (
            command.startswith(
                (
                    "find ",
                    "nginx -t",
                    "systemctl is-active",
                    "systemctl status",
                    "journalctl -u",
                    "certbot certificates",
                )
            )
            or "--dry-run" in command
        )
        assert not self.forbid_all, f"Command ran before operation approval: {command}"
        assert self.allow_mutations or read_only, f"Unapproved mutation: {command}"
        stdout = "/var/log/syslog.1.gz\n" if command.startswith("find ") else "active"
        return {"success": True, "returncode": 0, "stdout": stdout, "stderr": ""}


@pytest.fixture
def agent(monkeypatch):
    # Keep public execute_tool's real org scope, with isolated in-memory config.
    monkeypatch.setattr(
        "services.org_context.resolve_org_credentials", lambda *args: {}
    )
    monkeypatch.delenv("AGENT_EMERGENCY_STOP", raising=False)
    monkeypatch.delenv("AUTO_APPLY", raising=False)
    for key in ("CERTBOT_DNS_PLUGIN", "CERTBOT_WILDCARD_DOMAINS"):
        monkeypatch.delenv(key, raising=False)
    instance = DevOpsAgent.__new__(DevOpsAgent)
    runner = RecordingRunner()
    for attr, tool_type in HOST_TOOL_TYPES.items():
        setattr(instance, attr, tool_type(runner=runner))
    return instance, runner


def tool_inputs(name):
    values = {
        "file_path": "/etc/nginx/sites-enabled/app",
        "new_content": "server { listen 80; }\n",
    }
    return {key: values[key] for key in SCHEMAS[name].get("required", [])}


@pytest.mark.asyncio
@pytest.mark.parametrize("name", HOST_MUTATIONS)
@pytest.mark.parametrize("auto_apply", [None, "false"], ids=["default", "disabled"])
@pytest.mark.parametrize("host_source", ["inputs", "context"])
async def test_live_host_mutation_requires_approval(
    agent, monkeypatch, name, auto_apply, host_source
):
    instance, runner = agent
    if auto_apply is not None:
        monkeypatch.setenv("AUTO_APPLY", auto_apply)
    runner.forbid_all = True
    inputs = tool_inputs(name)
    if name in DRY_RUN_MUTATIONS:
        inputs["dry_run"] = False
    # A fake dry_run input cannot bypass operations without a dry_run schema.
    else:
        inputs["dry_run"] = True
    context = {}
    (inputs if host_source == "inputs" else context)["host"] = "203.0.113.10"

    result = await instance.execute_tool(name, inputs, context)

    assert runner.calls == [], result
    assert result.get("blocked") is True
    assert result.get("requires_approval") is True
    assert set(result) == {
        "blocked",
        "requires_approval",
        "command",
        "approval_payload",
        "message",
    }
    assert base64.b64decode(result["approval_payload"]).decode() == result["command"]
    assert "203.0.113.10" in result["command"]
    assert result["message"]


@pytest.mark.asyncio
@pytest.mark.parametrize("name", HOST_MUTATIONS)
async def test_auto_apply_allows_live_host_mutation(agent, monkeypatch, name):
    instance, runner = agent
    monkeypatch.setenv("AUTO_APPLY", "true")
    runner.allow_mutations = True
    inputs = {**tool_inputs(name), "host": "203.0.113.11"}
    if name in DRY_RUN_MUTATIONS:
        inputs["dry_run"] = False

    result = await instance.execute_tool(name, inputs)

    assert result.get("success", result.get("applied")) is True, result
    assert not result.get("blocked")
    assert runner.calls
    assert all(host == "203.0.113.11" for _, host in runner.calls)
    assert any(
        not command.startswith(
            (
                "find ",
                "nginx -t",
                "certbot certificates",
                "systemctl is-active",
                "systemctl status",
                "journalctl -u",
            )
        )
        for command, _ in runner.calls
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("name", HOST_MUTATIONS)
async def test_approval_replays_complete_host_operation(
    agent, monkeypatch, tmp_path, capsys, name
):
    instance, runner = agent
    runner.forbid_all = True
    inputs = {**tool_inputs(name), "host": "203.0.113.14"}
    if name in DRY_RUN_MUTATIONS:
        inputs["dry_run"] = False
    if name == "restart_nginx":
        inputs.update(
            config_path="/etc/nginx/sites-enabled/app",
            config_content="server { listen 80; }\n",
            reload_only=True,
        )
    approval = await instance.execute_tool(name, inputs)
    assert runner.calls == [], approval
    assert approval.get("requires_approval") is True

    # Execute the approved Python operation in-process, retaining real helper
    # behavior while replacing only constructors' external command runners.
    for tool_type in HOST_TOOL_TYPES.values():
        monkeypatch.setattr(
            importlib.import_module(tool_type.__module__),
            tool_type.__name__,
            lambda cls=tool_type: cls(runner=runner),
        )
    runner.forbid_all = False
    runner.allow_mutations = True

    async def approved_exec(command, host=None):
        argv = shlex.split(command)
        assert argv[:2] == ["python3", "-c"]
        assert len(argv) == 3
        script = tmp_path / "approved_operation.py"
        script.write_text(argv[2])
        await asyncio.to_thread(runpy.run_path, str(script))
        return {"success": True}

    executor = SafeExecutor()
    monkeypatch.setattr(executor, "_exec", approved_exec)
    result = await executor.run(approval["command"])

    assert result["success"] is True
    operation_result = json.loads(capsys.readouterr().out)
    assert operation_result.get("success", operation_result.get("applied")) is True
    assert runner.calls
    assert all(host == "203.0.113.14" for _, host in runner.calls)
    if name in {"apply_nginx_config", "restart_nginx"}:
        commands = [command for command, _ in runner.calls]
        write_index = next(
            i for i, command in enumerate(commands) if "write_bytes" in command
        )
        assert write_index < commands.index("nginx -t")
        assert commands[-1] == "systemctl reload nginx"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", DRY_RUN_MUTATIONS)
@pytest.mark.parametrize("dry_run", [None, True], ids=["default", "explicit"])
@pytest.mark.parametrize("auto_apply", ["false", "true"])
async def test_host_dry_run_remains_safe(agent, monkeypatch, name, dry_run, auto_apply):
    instance, runner = agent
    monkeypatch.setenv("AUTO_APPLY", auto_apply)
    inputs = {**tool_inputs(name), "host": "203.0.113.12"}
    if dry_run is not None:
        inputs["dry_run"] = dry_run

    result = await instance.execute_tool(name, inputs)

    assert result.get("dry_run") is True, result
    assert not result.get("blocked")
    assert not result.get("applied")


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(MUTATING_AGENT_TOOLS))
@pytest.mark.parametrize("auto_apply", ["false", "true"])
async def test_emergency_stop_blocks_every_mutating_agent_tool(
    agent, monkeypatch, name, auto_apply
):
    instance, runner = agent
    monkeypatch.setenv("AUTO_APPLY", auto_apply)
    monkeypatch.setenv("AGENT_EMERGENCY_STOP", "true")
    runner.forbid_all = True

    result = await instance.execute_tool(
        name, {"dry_run": False, "host": "203.0.113.13"}
    )

    assert result.get("blocked") is True, result
    assert result.get("emergency_stop") is True, result
    assert result.get("requires_approval") is False
    assert runner.calls == []
