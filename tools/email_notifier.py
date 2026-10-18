"""
Email notification system for dangerous operations and critical incidents.

This module sends email notifications when the agent detects operations
that require manual intervention or are too dangerous to auto-execute.
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class EmailNotifier:
    """
    Sends email notifications for dangerous operations and critical incidents.
    """
    
    def __init__(self):
        self.refresh_credentials()
        if not self.enabled:
            logger.warning("Email notifications are DISABLED. Set EMAIL_ENABLED=true to enable.")

    def refresh_credentials(self) -> None:
        self.enabled = os.getenv('EMAIL_ENABLED', 'false').lower() == 'true'
        self.smtp_host = os.getenv('EMAIL_SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('EMAIL_SMTP_PORT', '587'))
        self.smtp_user = os.getenv('EMAIL_SMTP_USER', '')
        self.smtp_password = os.getenv('EMAIL_SMTP_PASSWORD', '')
        self.from_email = os.getenv('EMAIL_FROM', self.smtp_user)
        self.to_emails = [e.strip() for e in os.getenv('EMAIL_TO', '').split(',') if e.strip()]
        self.cc_emails = [e.strip() for e in os.getenv('EMAIL_CC', '').split(',') if e.strip()]
    
    def send_dangerous_operation_alert(
        self,
        incident_id: str,
        operation: str,
        reason: str,
        recommended_commands: List[str],
        context: Dict,
        severity: str = "HIGH"
    ) -> bool:
        """
        Send email alert for dangerous operation that was blocked.
        
        Args:
            incident_id: Unique incident identifier
            operation: What operation was requested
            reason: Why it's dangerous
            recommended_commands: Manual commands for human to execute
            context: Additional context (logs, resource info, etc.)
            severity: CRITICAL, HIGH, MEDIUM, LOW
        
        Returns:
            True if email sent successfully, False otherwise
        """
        if not self.enabled:
            logger.info(f"Email disabled - would have sent alert for incident {incident_id}")
            return False
        
        subject = f"[DevOps Agent] 🚨 MANUAL INTERVENTION REQUIRED - {operation}"
        
        # Build email body
        body = self._build_dangerous_operation_email(
            incident_id=incident_id,
            operation=operation,
            reason=reason,
            recommended_commands=recommended_commands,
            context=context,
            severity=severity
        )
        
        return self._send_email(subject, body, is_html=False)
    
    def send_security_alert(
        self,
        incident_id: str,
        security_issue: str,
        severity: str,
        affected_resources: List[str],
        recommendations: List[str]
    ) -> bool:
        """
        Send security alert email.
        
        Args:
            incident_id: Unique incident identifier
            security_issue: Description of security issue
            severity: CRITICAL, HIGH, MEDIUM, LOW
            affected_resources: List of affected resources
            recommendations: Recommended actions
        
        Returns:
            True if email sent successfully
        """
        if not self.enabled:
            logger.info(f"Email disabled - would have sent security alert {incident_id}")
            return False
        
        subject = f"[DevOps Agent] 🔒 SECURITY ALERT - {security_issue}"
        
        body = f"""
SECURITY ALERT
==============

Severity: {severity}
Incident ID: {incident_id}
Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

SECURITY ISSUE:
{security_issue}

AFFECTED RESOURCES:
{self._format_list(affected_resources)}

RECOMMENDATIONS:
{self._format_list(recommendations)}

IMMEDIATE ACTIONS REQUIRED:
1. Review affected resources
2. Verify no unauthorized access
3. Check audit logs for anomalies
4. Take corrective action
5. Update security runbooks

DO NOT REPLY TO THIS EMAIL
Contact: security@yourcompany.com
"""
        
        return self._send_email(subject, body, is_html=False, priority='high')
    
    def send_compliance_violation_alert(
        self,
        incident_id: str,
        violation_type: str,
        compliance_framework: str,
        details: str,
        remediation_steps: List[str]
    ) -> bool:
        """
        Send compliance violation alert.
        
        Args:
            incident_id: Unique incident identifier
            violation_type: Type of violation
            compliance_framework: e.g., "PCI-DSS", "SOC2", "HIPAA"
            details: Violation details
            remediation_steps: Steps to fix
        
        Returns:
            True if email sent successfully
        """
        if not self.enabled:
            return False
        
        subject = f"[DevOps Agent] ⚠️ COMPLIANCE VIOLATION - {compliance_framework}"
        
        body = f"""
COMPLIANCE VIOLATION DETECTED
=============================

Framework: {compliance_framework}
Violation: {violation_type}
Incident ID: {incident_id}
Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

DETAILS:
{details}

REMEDIATION STEPS:
{self._format_list(remediation_steps)}

PRIORITY: HIGH
This violation may impact compliance certification.

Contact: compliance@yourcompany.com
"""
        
        return self._send_email(subject, body, is_html=False, priority='high')
    
    def send_critical_incident_alert(
        self,
        incident_id: str,
        incident_type: str,
        summary: str,
        impact: str,
        logs: str,
        next_steps: List[str]
    ) -> bool:
        """
        Send critical incident alert (P0/P1).
        
        Args:
            incident_id: Unique incident identifier
            incident_type: Type of incident
            summary: Brief summary
            impact: Impact description
            logs: Relevant logs
            next_steps: Recommended next steps
        
        Returns:
            True if email sent successfully
        """
        if not self.enabled:
            return False
        
        subject = f"[DevOps Agent] 🚨 P1 INCIDENT - {incident_type}"
        
        body = f"""
CRITICAL INCIDENT
=================

Incident ID: {incident_id}
Type: {incident_type}
Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
Priority: P1 - HIGH

SUMMARY:
{summary}

IMPACT:
{impact}

AGENT ANALYSIS:
The AI agent has analyzed this incident and determined it requires
immediate human attention. Auto-remediation was not attempted due to
the critical nature of the issue.

NEXT STEPS:
{self._format_list(next_steps)}

RELEVANT LOGS:
{logs[:1000]}  # First 1000 chars

ESCALATION:
If this incident is not resolved within 1 hour, it will be escalated
to the on-call manager.

View full details: https://agent-dashboard.company.com/incidents/{incident_id}
"""
        
        return self._send_email(subject, body, is_html=False, priority='urgent')

    def send_escalation_ticket(
        self,
        incident_id: str,
        org_id: str,
        summary: str,
        reasons: List[str],
        description: str,
        priority: str = "high",
    ) -> bool:
        """Send escalation email when agent cannot resolve — creates a human ticket."""
        if not self.enabled:
            logger.info(f"Email disabled - would have escalated {incident_id}")
            return False

        reason_text = "\n".join(f"  - {r}" for r in reasons)
        subject = f"[DevOps Agent] ESCALATION — {summary[:120]}"
        body = f"""
INCIDENT ESCALATION — Human action required
==========================================

{summary}

Incident ID: {incident_id}
Organization: {org_id}
Priority: {priority.upper()}
Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

Escalation reasons:
{reason_text}

DETAILS:
{description}

This incident was automatically escalated because the AI agent could not
resolve it within the configured time limit, encountered a database issue,
or lacked sufficient evidence to act safely.

Please investigate and update the team when resolved.
"""
        return self._send_email(subject, body, is_html=False, priority='urgent' if priority == 'critical' else 'high')
    
    def _build_dangerous_operation_email(
        self,
        incident_id: str,
        operation: str,
        reason: str,
        recommended_commands: List[str],
        context: Dict,
        severity: str
    ) -> str:
        """Build email body for dangerous operation alert."""
        
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Format context
        context_str = "\n".join([f"  - {k}: {v}" for k, v in context.items()])
        
        # Format commands
        commands_str = "\n".join([f"  {cmd}" for cmd in recommended_commands])
        
        email_body = f"""
MANUAL INTERVENTION REQUIRED
============================

Severity: {severity}
Incident ID: {incident_id}
Time: {timestamp}

OPERATION BLOCKED:
{operation}

WHY THIS IS DANGEROUS:
{reason}

AGENT RECOMMENDATION:
The DevOps AI Agent has detected this situation but WILL NOT execute
the operation automatically because it could cause data loss or service
disruption.

SUGGESTED COMMANDS FOR MANUAL EXECUTION:
{commands_str}

⚠️  WARNING: Review the situation carefully before executing these commands.

CONTEXT:
{context_str}

WHAT THE AGENT DID:
1. Detected the issue
2. Analyzed the situation
3. Determined manual intervention is required
4. Sent this notification
5. Logged the incident for audit

WHAT YOU SHOULD DO:
1. Review the context and logs
2. Verify the recommended commands are appropriate
3. Execute commands manually if you agree with the assessment
4. Update the agent's configuration if this becomes a common pattern
5. Document the resolution in the incident ticket

SAFETY REMINDER:
- Never delete resources without a backup
- Always test in staging first if possible
- Document your actions in the incident log
- Consider if there's a safer alternative

DO NOT REPLY TO THIS EMAIL
View incident details: https://agent-dashboard.company.com/incidents/{incident_id}
Contact: devops-team@yourcompany.com
"""
        
        return email_body
    
    def _format_list(self, items: List[str]) -> str:
        """Format list items with bullets."""
        if not items:
            return "  (none)"
        return "\n".join([f"  - {item}" for item in items])
    
    def _send_email(
        self,
        subject: str,
        body: str,
        is_html: bool = False,
        priority: str = 'normal'
    ) -> bool:
        """
        Send email via SMTP.
        
        Args:
            subject: Email subject
            body: Email body
            is_html: Whether body is HTML
            priority: normal, high, urgent
        
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled:
            logger.info(f"Email disabled. Subject: {subject}")
            return False
        
        if not self.to_emails:
            logger.error("No recipient emails configured (EMAIL_TO)")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            
            if self.cc_emails:
                msg['Cc'] = ', '.join(self.cc_emails)
            
            # Set priority
            if priority == 'urgent':
                msg['X-Priority'] = '1'
                msg['Importance'] = 'high'
            elif priority == 'high':
                msg['X-Priority'] = '2'
                msg['Importance'] = 'high'
            
            # Attach body
            if is_html:
                msg.attach(MIMEText(body, 'html'))
            else:
                msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                
                recipients = self.to_emails + self.cc_emails
                server.sendmail(self.from_email, recipients, msg.as_string())
            
            logger.info(f"Email sent successfully: {subject}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def test_email_configuration(self) -> bool:
        """
        Test email configuration by sending a test email.
        
        Returns:
            True if test email sent successfully
        """
        subject = "[DevOps Agent] Test Email - Configuration Verification"
        body = f"""
This is a test email from the DevOps AI Agent.

Configuration:
- SMTP Host: {self.smtp_host}
- SMTP Port: {self.smtp_port}
- From: {self.from_email}
- To: {', '.join(self.to_emails)}
- CC: {', '.join(self.cc_emails) if self.cc_emails else 'None'}
- Enabled: {self.enabled}

Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

If you received this email, your configuration is working correctly!
"""
        
        return self._send_email(subject, body, is_html=False)


# Singleton instance
_email_notifier = None


def get_email_notifier() -> EmailNotifier:
    """Get or create email notifier singleton."""
    global _email_notifier
    if _email_notifier is None:
        _email_notifier = EmailNotifier()
    return _email_notifier


# Convenience functions
def send_dangerous_operation_alert(*args, **kwargs) -> bool:
    """Send dangerous operation alert."""
    return get_email_notifier().send_dangerous_operation_alert(*args, **kwargs)


def send_security_alert(*args, **kwargs) -> bool:
    """Send security alert."""
    return get_email_notifier().send_security_alert(*args, **kwargs)


def send_compliance_violation_alert(*args, **kwargs) -> bool:
    """Send compliance violation alert."""
    return get_email_notifier().send_compliance_violation_alert(*args, **kwargs)


def send_critical_incident_alert(*args, **kwargs) -> bool:
    """Send critical incident alert."""
    return get_email_notifier().send_critical_incident_alert(*args, **kwargs)
