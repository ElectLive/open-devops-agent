"""
Slack Notifier
Sends rich incident summaries and interactive approval buttons to Slack.
"""
import json
import os
from typing import Optional

import httpx
import structlog

from services.pii_scrubber import scrub_text
from services.org_context import current_org_id

log = structlog.get_logger()

SEVERITY_EMOJI = {
    "info": "ℹ️",
    "warning": "⚠️",
    "critical": "🔴",
}


class SlackNotifier:
    def _webhook_url(self) -> str:
        return os.getenv("SLACK_WEBHOOK_URL", "")

    def _approval_channel(self) -> str:
        return os.getenv("SLACK_APPROVAL_CHANNEL", "#devops")

    def _bot_token(self) -> str:
        return os.getenv("SLACK_BOT_TOKEN", "")

    async def send_message(
        self,
        message: str,
        severity: str = "info",
        resolved: bool = False,
        requires_approval: bool = False,
        approval_command: Optional[str] = None,
    ):
        if not self._webhook_url():
            log.warning("SLACK_WEBHOOK_URL not set — skipping notification")
            return

        message = scrub_text(message)

        emoji = "✅" if resolved else SEVERITY_EMOJI.get(severity, "ℹ️")
        status_text = "RESOLVED" if resolved else severity.upper()

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} DevOps AI Agent — {status_text}",
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message},
            },
        ]

        if requires_approval and approval_command:
            import base64
            encoded = base64.b64encode(approval_command.encode()).decode()
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve & Execute"},
                        "style": "primary",
                        "action_id": "approve_action",
                        "value": json.dumps(
                            {
                                "org_id": current_org_id(),
                                "incident_id": "PENDING",
                                "command": encoded,
                            }
                        ),
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Reject"},
                        "style": "danger",
                        "action_id": "reject_action",
                        "value": "reject",
                    },
                ],
            })
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Pending command:*\n```{approval_command}```",
                },
            })

        payload = {"blocks": blocks}

        async with httpx.AsyncClient(timeout=10) as client:
            try:
                await client.post(self._webhook_url(), json=payload)
            except Exception as e:
                log.error("Slack notification failed", error=str(e))

    async def send_approval_request(self, description: str, command: str, encoded: str):
        await self.send_message(
            f"*Action requires approval:*\n{description}\n\n```{command}```",
            severity="warning",
            requires_approval=True,
            approval_command=command,
        )

    async def send_resolution(self, incident_id: str, result: dict):
        resolved = result.get("resolved", False)
        actions = result.get("actions", [])
        diagnosis = result.get("diagnosis", "")

        action_summary = ""
        if actions:
            successful = [a for a in actions if not a.get("result", {}).get("error")]
            action_summary = f"\n*Actions taken ({len(successful)}/{len(actions)} successful):*\n"
            for a in actions[:5]:
                tool = a.get("tool", "")
                res = a.get("result", {})
                ok = "✅" if not res.get("error") else "❌"
                action_summary += f"{ok} `{tool}`\n"

        message = (
            f"*Incident:* `{incident_id}`\n"
            f"*Status:* {'✅ Resolved' if resolved else '⚠️ Needs attention'}\n\n"
            f"{scrub_text(diagnosis[:800])}"
            f"{action_summary}"
        )

        await self.send_message(
            message,
            severity="info" if resolved else "warning",
            resolved=resolved,
        )

    async def send_error(self, incident_id: str, error: str):
        await self.send_message(
            f"*Agent error for incident `{incident_id}`:*\n```{error}```\n\nEscalating to on-call.",
            severity="critical",
        )

    async def send_escalation(
        self,
        incident_id: str,
        org_id: str,
        summary: str,
        reasons: list,
        description: str,
        duration_minutes: float = 0,
        priority: str = "high",
    ):
        """Notify team that incident requires human intervention / ticket created."""
        reason_labels = {
            "timeout_unresolved": "⏱️ Exceeded time limit",
            "unresolved": "❌ Unresolved",
            "database_issue": "🗄️ Database issue",
            "agent_error": "💥 Agent error",
            "not_grounded": "⚠️ Insufficient evidence",
            "max_steps_reached": "🔄 Max steps reached",
        }
        reason_text = "\n".join(
            f"• {reason_labels.get(r, r)}" for r in reasons
        )
        ticket_note = ""
        if os.getenv("JIRA_ENABLED", "false").lower() == "true":
            ticket_note += "\n_Jira ticket may have been created._"
        if os.getenv("ZOHO_ENABLED", "false").lower() == "true":
            ticket_note += "\n_Zoho Desk ticket may have been created._"

        message = (
            f"*🎫 ESCALATION — Human intervention required*\n\n"
            f"*Incident:* `{incident_id}`\n"
            f"*Org:* `{org_id}`\n"
            f"*Priority:* {priority.upper()}\n"
            f"*Duration:* {duration_minutes:.1f} min (timeout: {os.getenv('ESCALATION_TIMEOUT_MINUTES', '10')} min)\n\n"
            f"*Reasons:*\n{reason_text}\n\n"
            f"*Summary:* {scrub_text(summary)}\n\n"
            f"*Details:*\n{scrub_text(description[:1500])}"
            f"{ticket_note}"
        )
        await self.send_message(message, severity="critical", resolved=False)

    async def send_fix_suggestion(
        self,
        title: str,
        description: str,
        commands: list,
        config_snippets: Optional[list] = None,
        verification_steps: Optional[list] = None,
    ):
        """Notify team of a validated non-destructive fix suggestion from Claude."""
        cmd_text = "\n".join(f"• `{c}`" for c in commands[:8])
        config_text = ""
        if config_snippets:
            config_text = "\n*Config changes:*\n" + "\n".join(
                f"```{s[:500]}```" for s in config_snippets[:2]
            )
        verify_text = ""
        if verification_steps:
            verify_text = "\n*Verify:*\n" + "\n".join(f"• {s}" for s in verification_steps[:5])

        message = (
            f"*Suggested fix (non-destructive):* {scrub_text(title)}\n\n"
            f"{scrub_text(description)}\n\n"
            f"*Commands to run:*\n{cmd_text}"
            f"{config_text}"
            f"{verify_text}"
        )
        await self.send_message(message, severity="info", resolved=False)
