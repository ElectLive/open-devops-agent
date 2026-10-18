"""Jira issue creation for escalated incidents."""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx
import structlog

from services.pii_scrubber import scrub_text

log = structlog.get_logger()


class JiraClient:
    def __init__(self):
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        self.enabled = os.getenv("JIRA_ENABLED", "false").lower() == "true"
        self.base_url = os.getenv("JIRA_URL", "").rstrip("/")
        self.email = os.getenv("JIRA_EMAIL", "")
        self.api_token = os.getenv("JIRA_API_TOKEN", "")
        self.project_key = os.getenv("JIRA_PROJECT_KEY", "OPS")
        self.issue_type = os.getenv("JIRA_ISSUE_TYPE", "Task")
        self.priority_map = {
            "critical": os.getenv("JIRA_PRIORITY_CRITICAL", "Highest"),
            "high": os.getenv("JIRA_PRIORITY_HIGH", "High"),
            "medium": os.getenv("JIRA_PRIORITY_MEDIUM", "Medium"),
            "low": os.getenv("JIRA_PRIORITY_LOW", "Low"),
        }

    def is_configured(self) -> bool:
        return self.enabled and bool(self.base_url and self.email and self.api_token)

    async def create_ticket(
        self,
        summary: str,
        description: str,
        priority: str = "high",
        labels: Optional[list] = None,
    ) -> Dict[str, Any]:
        if not self.is_configured():
            return {"skipped": True, "reason": "Jira not configured"}

        url = f"{self.base_url}/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": scrub_text(summary)[:255],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": scrub_text(description)[:32000]}
                            ],
                        }
                    ],
                },
                "issuetype": {"name": self.issue_type},
                "priority": {"name": self.priority_map.get(priority, "High")},
                "labels": labels or ["devops-ai-agent", "auto-escalation"],
            }
        }

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.post(
                    url,
                    json=payload,
                    auth=(self.email, self.api_token),
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    key = data.get("key")
                    log.info("Jira ticket created", key=key)
                    return {
                        "created": True,
                        "key": key,
                        "url": f"{self.base_url}/browse/{key}",
                    }
                return {"created": False, "error": resp.text, "status": resp.status_code}
            except Exception as e:
                log.error("Jira ticket creation failed", error=str(e))
                return {"created": False, "error": str(e)}
