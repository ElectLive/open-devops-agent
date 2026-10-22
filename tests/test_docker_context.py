import os

os.environ.setdefault("ANTHROPIC_API_KEY", "dummy-test-key")

import pytest

from agent.core import DevOpsAgent
from services.pii_scrubber import scrub_dict


CONTEXT = {
    "type": "cicd",
    "labels": {"cicd_platform": "github"},
    "repo": "203.0.113.10/org/repo",
    "run_id": 12345,
}

FAILED_DOCKER_LOG = (
    "Step 1/2 : FROM python:3.11-slim\n"
    " ---> Using cache\n"
    "Step 2/2 : RUN pip install -r requirements.txt\n"
    + "Collecting application dependencies\n" * 100
    + "ERROR: Could not find a version that satisfies the requirement missing-package\n"
    "ERROR: No matching distribution found for missing-package\n"
    "failed to install application dependencies\n"
    "The command '/bin/sh -c pip install -r requirements.txt' returned a non-zero code: 1\n"
)

SUCCESSFUL_DOCKER_LOG = (
    "Step 1/2 : FROM python:3.11-slim\n"
    " ---> Using cache\n"
    "Step 2/2 : RUN pip install -r requirements.txt\n"
    "Successfully installed application dependencies\n"
    "Successfully built abc123\n"
)


@pytest.fixture
def ci_logs():
    return {
        "run_id": 12345,
        "workflow": "Build and test",
        "branch": "main",
        "commit": "abc12345",
        "trigger": "push",
        "url": "https://203.0.113.10/org/repo/actions/runs/12345",
        "failed_jobs": [
            {
                "name": "Build image",
                "steps": [{"name": "Build", "conclusion": "failure", "number": 2}],
                "logs": FAILED_DOCKER_LOG,
            }
        ],
    }


class TestDockerContext:
    @pytest.mark.asyncio
    async def test_docker_fragments_are_scrubbed_before_tail_slicing(self, ci_logs, monkeypatch):
        agent = DevOpsAgent()
        begin = "-----BEGIN PRIVATE KEY-----"
        end = "-----END PRIVATE KEY-----"
        body_line = "A" * 64
        inline_body = "B" * 32
        log = (
            "Step 1/2 : FROM python:3.11-slim\n"
            + begin + "\n"
            + (body_line + "\n") * 60
            + end + "\n"
            "Step 2/2 : RUN make\n"
            + "ERROR: failed to build " + begin + inline_body + end + "\n"
        )
        # The raw tail loses BEGIN while retaining synthetic body lines.
        assert log.index(begin) < len(log) - 3000 < log.index(end)
        ci_logs["failed_jobs"][0]["logs"] = log

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)
        scrubbed = scrub_dict(enriched)

        assert scrubbed["docker_build_error"]["errors"] == [
            "ERROR: failed to build [REDACTED_PRIVATE_KEY]",
        ]

        def assert_scrubbed(value):
            if isinstance(value, dict):
                for child in value.values():
                    assert_scrubbed(child)
            elif isinstance(value, list):
                for child in value:
                    assert_scrubbed(child)
            elif isinstance(value, str):
                assert body_line not in value
                assert inline_body not in value

        assert_scrubbed(scrubbed["ci_logs"])
        assert_scrubbed(scrubbed["docker_build_error"])

    @pytest.mark.asyncio
    async def test_failed_docker_build_adds_first_parsed_error(self, ci_logs, monkeypatch):
        # Docker-failed direction: the first matching failed log supplies exact parser values.
        agent = DevOpsAgent()
        ci_logs["failed_jobs"].insert(0, {
            "name": "Build and test",
            "steps": [{"name": "Test", "conclusion": "failure", "number": 3}],
            "logs": SUCCESSFUL_DOCKER_LOG,
        })
        ci_logs["failed_jobs"].append({
            "name": "Build another image",
            "steps": [{"name": "Build", "conclusion": "failure", "number": 2}],
            "logs": "Step 1 : RUN make\nERROR: make failed\n",
        })

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("docker_build_error") == {
            "step": "Step 1/2 : FROM python:3.11-slim",
            "errors": [
                "ERROR: Could not find a version that satisfies the requirement missing-package",
                "ERROR: No matching distribution found for missing-package",
                "failed to install application dependencies",
            ],
            "raw": FAILED_DOCKER_LOG[-3000:],
        }
        assert enriched.get("ci_logs") == ci_logs
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_non_docker_failure_keeps_context(self, ci_logs, monkeypatch):
        # Non-Docker direction: a failing Docker-related test is not a Docker build log.
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = (
            "============================= test session starts =============================\n"
            "collected 2 items\n"
            "tests/test_docker.py::test_container_health FAILED\n"
            "E   AssertionError: container did not become healthy\n"
            "========================= 1 failed, 1 passed in 0.42s =========================\n"
        )

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("ci_logs") == ci_logs
        assert "docker_build_error" not in enriched
        assert "collection_error" not in enriched

    @pytest.mark.asyncio
    async def test_collector_failure_keeps_collection_error(self, monkeypatch):
        # Collector-failure direction: collection errors remain non-fatal without Docker data.
        agent = DevOpsAgent()

        async def fake_collect(repo, run_id):
            raise RuntimeError("CI collection unavailable")

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("collection_error") == "CI collection unavailable"
        assert "docker_build_error" not in enriched
        assert "ci_logs" not in enriched

    @pytest.mark.asyncio
    async def test_successful_docker_build_keeps_context(self, ci_logs, monkeypatch):
        # Successful Docker build direction: step markers alone do not add an error.
        agent = DevOpsAgent()
        ci_logs["failed_jobs"][0]["logs"] = SUCCESSFUL_DOCKER_LOG

        async def fake_collect(repo, run_id):
            return ci_logs

        monkeypatch.setattr(agent.github_collector, "collect", fake_collect)
        enriched = await agent._collect_context(CONTEXT)

        assert enriched.get("ci_logs") == ci_logs
        assert "docker_build_error" not in enriched
        assert "collection_error" not in enriched
