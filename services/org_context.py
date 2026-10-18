"""
Apply per-org credentials for the duration of a request/tool call.

Ensures org A's Slack/GitHub/Anthropic keys are never used for org B.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator, Optional

import structlog

from services.org_config import ORG_CREDENTIAL_KEYS, OrgConfig, resolve_org_credentials

log = structlog.get_logger()


@contextmanager
def org_credentials(org_id: str, org_config: Optional[OrgConfig] = None) -> Generator[dict, None, None]:
    """
    Temporarily overlay os.environ with the org's own credentials.
    Yields the merged credential dict (keys only, for logging).
    """
    org_config = org_config or OrgConfig()
    creds = resolve_org_credentials(org_id, org_config)
    previous: dict[str, Optional[str]] = {}

    for key in ORG_CREDENTIAL_KEYS:
        if key in creds:
            previous[key] = os.environ.get(key)
            os.environ[key] = str(creds[key])

    try:
        yield {k: True for k in creds}
    finally:
        for key, old in previous.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


_CREDENTIAL_CLIENTS = (
    "github_collector",
    "gitlab_collector",
    "jenkins_collector",
    "bamboo_collector",
    "azure_devops_collector",
    "argocd_collector",
    "aws_collector",
    "gcp_collector",
    "azure_collector",
    "github_tools",
    "cicd_tools",
    "cloud_tools",
    "argocd_tools",
    "k8s_collector",
    "k8s_tools",
    "helm_tools",
)


def _refresh_client(client: object) -> None:
    refresh = getattr(client, "refresh_credentials", None)
    if callable(refresh):
        refresh()
        return
    reset = getattr(client, "reset", None)
    if callable(reset):
        reset()


def refresh_agent_credentials(agent: object) -> None:
    """Re-read env-backed clients after an org credential overlay."""
    if hasattr(agent, "client"):
        agent.client = None
    for name in _CREDENTIAL_CLIENTS:
        client = getattr(agent, name, None)
        if client is not None:
            _refresh_client(client)
