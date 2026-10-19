"""Org credential overlays must reach clients that cache tokens at startup."""
from types import SimpleNamespace

from collectors.argocd import ArgoCDCollector
from collectors.azure_devops import AzureDevOpsCollector
from collectors.bamboo import BambooCollector
from collectors.gitlab import GitLabCollector
from collectors.jenkins import JenkinsCollector
from collectors.k8s import K8sCollector
from services.escalation import EscalationService
from services.org_context import refresh_agent_credentials
from tools.cicd_tools import CICDTools
from tools.cloud_tools import CloudTools
from tools.github_tools import GitHubTools
from tools.pagerduty_tools import PagerDutyClient


def test_gitlab_collector_rereads_token_after_overlay(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "")
    collector = GitLabCollector()
    assert collector.token == ""

    monkeypatch.setenv("GITLAB_TOKEN", "glpat-acme")
    assert collector.token == ""
    collector.refresh_credentials()
    assert collector.token == "glpat-acme"
    assert collector.headers["PRIVATE-TOKEN"] == "glpat-acme"


def test_refresh_agent_credentials_updates_cached_clients(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "")
    monkeypatch.setenv("JENKINS_API_TOKEN", "")
    monkeypatch.setenv("JENKINS_USERNAME", "ops")
    monkeypatch.setenv("BAMBOO_PASSWORD", "")
    monkeypatch.setenv("AZURE_DEVOPS_PAT", "")
    monkeypatch.setenv("ARGOCD_AUTH_TOKEN", "")
    monkeypatch.setenv("GITHUB_TOKEN", "")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    agent = SimpleNamespace(
        client=object(),
        gitlab_collector=GitLabCollector(),
        jenkins_collector=JenkinsCollector(),
        bamboo_collector=BambooCollector(),
        azure_devops_collector=AzureDevOpsCollector(),
        argocd_collector=ArgoCDCollector(),
        github_tools=GitHubTools(),
        cicd_tools=CICDTools(),
        cloud_tools=CloudTools(),
        k8s_collector=K8sCollector(),
    )
    agent.k8s_collector._loaded = True

    monkeypatch.setenv("GITLAB_TOKEN", "glpat-acme")
    monkeypatch.setenv("JENKINS_API_TOKEN", "jenkins-acme")
    monkeypatch.setenv("BAMBOO_PASSWORD", "bamboo-acme")
    monkeypatch.setenv("BAMBOO_USERNAME", "bamboo")
    monkeypatch.setenv("AZURE_DEVOPS_PAT", "ado-acme")
    monkeypatch.setenv("ARGOCD_AUTH_TOKEN", "argo-acme")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp-acme")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")

    refresh_agent_credentials(agent)

    assert agent.client is None
    assert agent.gitlab_collector.token == "glpat-acme"
    assert agent.jenkins_collector.token == "jenkins-acme"
    assert agent.jenkins_collector.auth == ("ops", "jenkins-acme")
    assert agent.bamboo_collector.password == "bamboo-acme"
    assert agent.azure_devops_collector.pat == "ado-acme"
    assert agent.azure_devops_collector.headers["Authorization"].startswith("Basic ")
    assert agent.argocd_collector.auth_token == "argo-acme"
    assert agent.github_tools.token == "ghp-acme"
    assert agent.github_tools.headers["Authorization"] == "Bearer ghp-acme"
    assert agent.cicd_tools.gitlab_token == "glpat-acme"
    assert agent.cloud_tools.aws_region == "eu-west-1"
    assert agent.k8s_collector._loaded is False


def test_escalation_rereads_pagerduty_token(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_TOKEN", "")
    service = EscalationService()
    assert service.pagerduty.token == ""

    monkeypatch.setenv("PAGERDUTY_ENABLED", "true")
    monkeypatch.setenv("PAGERDUTY_TOKEN", "pd-acme")
    monkeypatch.setenv("PAGERDUTY_SERVICE_ID", "PSERVICE")
    monkeypatch.setenv("PAGERDUTY_FROM_EMAIL", "ops@example.com")
    service.refresh_credentials()

    assert service.pagerduty.token == "pd-acme"
    assert service.pagerduty.is_configured() is True
