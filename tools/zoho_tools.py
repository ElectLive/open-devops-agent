"""Zoho Desk ticket creation for escalated incidents."""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx
import structlog

from services.pii_scrubber import scrub_text

log = structlog.get_logger()


class ZohoDeskClient:
    def __init__(self):
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        self.enabled = os.getenv("ZOHO_ENABLED", "false").lower() == "true"
        self.org_id = os.getenv("ZOHO_DESK_ORG_ID", "")
        self.access_token = os.getenv("ZOHO_ACCESS_TOKEN", "")
        self.department_id = os.getenv("ZOHO_DEPARTMENT_ID", "")
        self.base_url = os.getenv("ZOHO_DESK_URL", "https://desk.zoho.com/api/v1")

    def is_configured(self) -> bool:
        return self.enabled and bool(self.org_id and self.access_token and self.department_id)

    async def create_ticket(
        self,
        subject: str,
        description: str,
        priority: str = "High",
        email: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.is_configured():
            return {"skipped": True, "reason": "Zoho Desk not configured"}

        url = f"{self.base_url}/tickets"
        payload = {
            "subject": scrub_text(subject)[:255],
            "description": scrub_text(description)[:32000],
            "departmentId": self.department_id,
            "priority": priority,
            "status": "Open",
            "channel": "DevOps AI Agent",
        }
        if email:
            payload["email"] = email
        elif os.getenv("ZOHO_CONTACT_EMAIL"):
            payload["email"] = os.getenv("ZOHO_CONTACT_EMAIL")

        headers = {
            "Authorization": f"Zoho-oauthtoken {self.access_token}",
            "orgId": self.org_id,
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code in (200, 201):
                    data = resp.json()
                    ticket_id = data.get("id") or data.get("ticketNumber")
                    log.info("Zoho ticket created", ticket_id=ticket_id)
                    return {"created": True, "id": ticket_id, "data": data}
                return {"created": False, "error": resp.text, "status": resp.status_code}
            except Exception as e:
                log.error("Zoho ticket creation failed", error=str(e))
                return {"created": False, "error": str(e)}
