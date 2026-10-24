# Security & Safety Summary

## Quick Reference: What the Agent Will and Won't Do

### ✅ SAFE Operations (Agent Can Perform)

**Read-Only** (Always allowed):
- Get logs and metrics
- Describe resource status
- List resources
- Health checks
- Diagnostic queries

**Safe Actions** (Requires approval):
- Restart pods/services (graceful)
- Scale resources UP (never down to 0)
- Apply configuration changes
- Create pull/merge requests
- Retry failed builds
- Rollback to known-good versions

### ⚠️ Dangerous Operations (Email Alert Only)

The agent will **NEVER execute** these. Instead, it sends email with manual commands:

- Delete pods, deployments, services
- Terminate instances
- Drop databases or tables
- Format disks
- Remove files or directories
- Scale to zero
- Force operations
- Modify security groups
- Change firewall rules
- Delete backups

### 🚫 Permanently Blocked

These patterns are **hardcoded blocked**:
```
kubectl delete
rm -rf
DROP DATABASE
aws ec2 terminate-instances
gcloud compute instances delete
az vm delete
--force-delete
--replicas=0
```

## Email Notification System

### When Emails Are Sent

1. **Dangerous Operation Detected**
   ```
   Subject: [DevOps Agent] 🚨 MANUAL INTERVENTION REQUIRED
   Content: Manual commands provided for review
   ```

2. **Security Vulnerability Found**
   ```
   Subject: [DevOps Agent] 🔒 SECURITY ALERT
   Content: Vulnerability details and remediation steps
   ```

3. **Compliance Violation**
   ```
   Subject: [DevOps Agent] ⚠️ COMPLIANCE VIOLATION
   Content: Framework, violation type, remediation deadline
   ```

4. **Critical Incident (P0/P1)**
   ```
   Subject: [DevOps Agent] 🚨 P1 INCIDENT
   Content: Impact, analysis, next steps
   ```

### Configure Emails

```bash
# .env
EMAIL_ENABLED=true
EMAIL_TO=sre-team@company.com,oncall@company.com
EMAIL_CC=security@company.com
```

**Test Configuration**:
```python
from tools.email_notifier import get_email_notifier

notifier = get_email_notifier()
notifier.test_email_configuration()
```

## DevSecOps Features

### Security Scanning

**Automatically detects**:
- Privileged containers
- Running as root user
- Exposed secrets (passwords, API keys)
- Unencrypted HTTP
- Missing security contexts
- Latest/unversioned tags
- Debug mode in production
- Overly permissive RBAC

**Example**:
```json
{
  "type": "exposed_secret",
  "severity": "CRITICAL",
  "description": "API key found in ConfigMap",
  "recommendation": "Use Kubernetes Secret instead",
  "location": "configmap/app-config"
}
```

### Compliance Frameworks

**Supported**:
- CIS Kubernetes Benchmark
- SOC 2
- PCI-DSS
- HIPAA
- GDPR

**Enable**:
```bash
ENABLE_COMPLIANCE_CHECKS=true
COMPLIANCE_FRAMEWORKS=CIS,SOC2,PCI
```

## Approval Workflow

```
┌─────────────────────────────────────────┐
│  Incident Detected                      │
└────────────┬────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────┐
│  Agent Analyzes Issue                   │
└────────────┬────────────────────────────┘
             │
             ▼
      Is it dangerous?
             │
        ┌────┴────┐
        │         │
       YES       NO
        │         │
        ▼         ▼
  ┌─────────┐ ┌──────────┐
  │ BLOCK   │ │ Is it    │
  │ Send    │ │ safe?    │
  │ Email   │ │          │
  └─────────┘ └────┬─────┘
                   │
              ┌────┴────┐
              │         │
             YES       NO
              │         │
              ▼         ▼
        ┌──────────┐ ┌─────────────┐
        │ Execute  │ │ Request     │
        │ (dry-run)│ │ Approval    │
        └────┬─────┘ └──────┬──────┘
             │              │
             ▼              ▼
        ┌──────────────────────┐
        │ Notify Team          │
        │ Update Audit Log     │
        └──────────────────────┘
```

## Audit Trail

Every action is logged:

```json
{
  "timestamp": "2026-06-12T15:30:00Z",
  "incident_id": "INC-123",
  "action_type": "dangerous_operation_blocked",
  "operation": "kubectl delete pod api-service",
  "reason": "Deletion is destructive",
  "severity": "HIGH",
  "email_sent": true,
  "email_recipients": ["sre-team@company.com"],
  "manual_commands_provided": [
    "kubectl describe pod api-service -n production",
    "# If needed: kubectl delete pod api-service -n production"
  ],
  "ai_reasoning": "Pod is crashing due to config error. Recommended to fix config first rather than delete.",
  "security_scan": {
    "performed": true,
    "findings": 0
  }
}
```

## Emergency Procedures

### Emergency Stop

**Immediate shutdown**:
```bash
# Via API
curl -X POST https://agent.company.com/emergency-stop \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Via environment variable
export AGENT_EMERGENCY_STOP=true
```

**When to use**:
- Agent behaving unexpectedly
- Security incident suspected
- Need to pause all operations
- Production emergency

### Investigating Blocked Operations

```bash
# View all blocked operations
curl -H "Authorization: Bearer $API_TOKEN" https://agent.company.com/audit | jq '.[] | select(.action_type == "dangerous_operation_blocked")'

# Check email notification status
curl -H "Authorization: Bearer $API_TOKEN" https://agent.company.com/audit | jq '.[] | select(.email_sent == false)'

# Security findings
curl https://agent.company.com/security/findings
```

## Configuration Checklist

Before deployment:

- [ ] Set `AUTO_APPLY=false`
- [ ] Configure email alerts (`EMAIL_TO`, `EMAIL_CC`)
- [ ] Enable security scanning
- [ ] Set compliance frameworks
- [ ] Configure RBAC with minimal permissions
- [ ] Test email configuration
- [ ] Review SECURITY_POLICY.md
- [ ] Set up audit log monitoring
- [ ] Configure emergency stop access
- [ ] Document incident response procedures

## Monitoring

**Key Metrics**:
```yaml
agent_dangerous_operations_blocked_total: 12
agent_emails_sent_total: 8
agent_security_findings_total{severity="CRITICAL"}: 2
agent_compliance_violations_total: 1
agent_safe_operations_executed_total: 156
agent_approval_requests_total: 24
agent_approvals_granted_total: 20
```

**Alerts**:
```yaml
# Alert if dangerous operations are frequent
- alert: HighBlockedOperations
  expr: increase(agent_dangerous_operations_blocked_total[1h]) > 5

# Alert on critical security findings
- alert: CriticalSecurityFindings
  expr: agent_security_findings_total{severity="CRITICAL"} > 0

# Alert if emails aren't being sent
- alert: EmailDeliveryFailure
  expr: increase(agent_email_failed_total[5m]) > 0
```

## Best Practices

1. **Start Conservative**
   - AUTO_APPLY=false
   - Review all decisions for 2 weeks
   - Gradually increase trust

2. **Monitor Closely**
   - Check audit logs daily
   - Review blocked operations
   - Investigate email alerts

3. **Security First**
   - Enable all security scanning
   - Set up compliance checks
   - Regular security audits

4. **Have a Plan**
   - Document emergency procedures
   - Test emergency stop
   - Practice incident response

5. **Keep Updated**
   - Review security policy monthly
   - Update blocked patterns
   - Refresh credentials regularly

## Getting Help

- **Security Issues**: security@yourcompany.com
- **Blocked Operation Questions**: Review email for context
- **False Positives**: Update security scanner rules
- **Emergencies**: Use emergency stop, then investigate

## Resources

- [SECURITY_POLICY.md](SECURITY_POLICY.md) - Complete security policy
- [DEVSECOPS_GUIDE.md](DEVSECOPS_GUIDE.md) - DevSecOps best practices
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [DEPLOYMENT.md](DEPLOYMENT.md) - Production deployment

---

**Remember: The agent is designed to assist, not replace human judgment. When in doubt, it will always err on the side of caution and notify you.**
