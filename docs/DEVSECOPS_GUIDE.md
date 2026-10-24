# DevSecOps Guide

## 🔒 Security-First DevOps Automation

This guide covers the DevSecOps features and best practices for the DevOps AI Agent.

## Core Philosophy

```
🛡️ SAFETY FIRST: Never Delete, Never Destroy, Always Notify
```

The agent follows these principles:
1. **Read-only by default** - Most operations just gather information
2. **Email alerts for dangerous operations** - Never execute destructive commands
3. **Multi-level approval gates** - Human oversight for critical actions
4. **Comprehensive audit trail** - Every decision is logged
5. **Security scanning** - Automatic detection of vulnerabilities
6. **Compliance checks** - Validate against security standards

---

## Security Features

### 1. Operation Safety Levels

```yaml
SAFE (Auto-allowed):
  - Read operations (logs, status, describe)
  - Diagnostic queries
  - Health checks
  - Metrics collection

REQUIRES_APPROVAL:
  - Restart services
  - Scale resources UP
  - Update configurations
  - Rollback to known versions

DANGEROUS (Email only, no execution):
  - Delete resources
  - Terminate instances
  - Drop databases
  - Format storage
  - Scale to zero
  - Force operations

BLOCKED (Never suggested):
  - Data loss operations
  - Irreversible changes
  - Production database modifications
```

### 2. Email Notification System

Configure email alerts for dangerous operations:

```bash
# .env
EMAIL_ENABLED=true
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USER=devops-agent@company.com
EMAIL_SMTP_PASSWORD=your-app-password
EMAIL_FROM=devops-agent@company.com
EMAIL_TO=sre-team@company.com,oncall@company.com
EMAIL_CC=security@company.com
```

**Email Triggers**:
- Dangerous operation detected
- Security vulnerability found
- Compliance violation detected
- Critical incident (P0/P1)
- Manual intervention required
- Approval timeout

**Example Email**:
```
Subject: [DevOps Agent] 🚨 MANUAL INTERVENTION REQUIRED - Pod Deletion

The agent detected a need to delete a pod but this operation
is blocked for safety. Manual commands provided below.

WHAT HAPPENED:
Pod crash-loop-backoff detected in production namespace

AGENT RECOMMENDATION:
Delete and recreate the pod

WHY THIS REQUIRES MANUAL ACTION:
Pod deletion is a destructive operation that could cause downtime

SUGGESTED COMMANDS:
# Review the pod first
kubectl describe pod api-service-xyz -n production

# If you decide to proceed:
kubectl delete pod api-service-xyz -n production

SAFETY REMINDER:
- Always have backups
- Test in staging first
- Verify during business hours
- Notify team before proceeding
```

### 3. Security Scanning

The agent automatically scans for:

#### Container Security
- Privileged containers
- Running as root
- Missing security context
- Added Linux capabilities
- Host network access
- Latest/unversioned tags

#### Configuration Security
- Exposed secrets (passwords, API keys, tokens)
- Unencrypted HTTP connections
- Debug mode in production
- Missing resource limits
- Overly permissive RBAC

#### Compliance Violations
- CIS Kubernetes Benchmark
- SOC 2 requirements
- PCI-DSS standards
- HIPAA regulations
- GDPR compliance

**Example Scan Result**:
```json
{
  "scan_type": "kubernetes_manifest",
  "total_findings": 5,
  "severity_summary": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 2,
    "LOW": 0
  },
  "findings": [
    {
      "type": "privileged_container",
      "severity": "HIGH",
      "description": "Container running with privileged mode",
      "recommendation": "Remove privileged mode",
      "cis_benchmark": "CIS-K8s-5.2.1"
    }
  ]
}
```

### 4. Blocked Operations

**Permanently blocked commands** (will never execute):

```python
# Deletion
kubectl delete
helm uninstall
aws ec2 terminate-instances
gcloud compute instances delete
az vm delete
rm -rf
DROP DATABASE
DROP TABLE

# Formatting/Destructive
format
mkfs
dd if=/dev/zero

# Force operations
--force-delete
--no-preserve-root

# Scaling to zero
--replicas=0
--min-instances=0
```

When agent detects these:
1. ✅ Block execution immediately
2. ✅ Log the attempt with full context
3. ✅ Send email to operations team
4. ✅ Provide manual commands for review
5. ✅ Update audit trail

---

## DevSecOps Best Practices

### Secrets Management

**DO**:
- ✅ Use Kubernetes Secrets
- ✅ Use AWS Secrets Manager / GCP Secret Manager
- ✅ Use HashiCorp Vault
- ✅ Rotate secrets regularly
- ✅ Use service accounts with minimal permissions

**DON'T**:
- ❌ Hardcode secrets in code
- ❌ Store secrets in environment variables (in Dockerfiles)
- ❌ Commit secrets to git
- ❌ Use default passwords
- ❌ Share secrets in Slack/email

**Agent Detection**:
The agent scans for:
- Patterns like `password=`, `api_key=`, `secret=`
- AWS access keys
- Private keys
- Database connection strings

**When found**:
```
CRITICAL: Possible exposed secret detected
Location: deployment.yaml line 42
Pattern: ENV PASSWORD=admin123
Recommendation: Use Kubernetes Secret instead
```

### Network Security

**Kubernetes Network Policies**:
```yaml
# Agent verifies network policies exist
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

**Agent Checks**:
- ✅ Default deny network policies
- ✅ TLS/HTTPS for all external traffic
- ✅ No host network usage
- ✅ Service mesh (Istio/Linkerd) mTLS

### RBAC & Least Privilege

**Agent follows**:
```yaml
# Minimal K8s permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "events"]
  verbs: ["get", "list", "watch"]

# NO permissions for:
- delete (any resource)
- create (pods, deployments)
- update (critical resources)
```

**Checks RBAC**:
- No `*` permissions
- No cluster-admin bindings (except for admins)
- Service accounts with minimal scope
- Namespace-scoped roles (not cluster roles)

### Container Security

**Dockerfile Best Practices**:
```dockerfile
# Good Dockerfile (passes agent checks)
FROM python:3.9-slim as base

# Create non-root user
RUN useradd -m -u 1000 appuser

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Switch to non-root
USER appuser

# Add health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "app.py"]
```

**Agent Detects**:
- ❌ Running as root
- ❌ Using `latest` tag
- ❌ Missing health checks
- ❌ Secrets in ENV
- ❌ No package cleanup

### Kubernetes Security Context

**Required Security Context**:
```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
      runAsNonRoot: true
```

**Agent Enforces**:
- ✅ runAsNonRoot: true
- ✅ No privilege escalation
- ✅ Drop all capabilities
- ✅ Read-only root filesystem
- ❌ Never privileged: true

### Compliance Frameworks

#### CIS Kubernetes Benchmark

**Automated Checks**:
- 5.2.1: Minimize privileged containers
- 5.2.2: Minimize containers that share host network
- 5.2.3: Minimize containers with allowPrivilegeEscalation
- 5.2.4: Minimize containers with hostPath volumes
- 5.2.5: Minimize containers with hostPorts
- 5.2.6: Minimize use of host networking
- 5.2.7: Minimize containers running with root privileges
- 5.2.8: Limit use of host IPC
- 5.2.9: Minimize Linux Kernel module loading

#### SOC 2

**Controls**:
- CC6.1: Logical and physical access controls
- CC6.2: Prior to issuing system credentials
- CC6.3: Removes access when no longer required
- CC6.6: Protects against infection by malicious software
- CC7.2: System monitoring

**Agent Implementation**:
- Access control via RBAC
- Audit logging of all actions
- Automatic access reviews
- Malware scanning of images
- Real-time monitoring and alerting

#### PCI-DSS

**Requirements**:
- 2.2: Remove unnecessary services
- 6.5: Address common coding vulnerabilities
- 8.7: Restrict access to databases
- 10.2: Audit logging
- 10.3: Record audit trail entries

**Agent Compliance**:
- Scans for unnecessary services
- Detects SQL injection patterns
- Enforces database access controls
- Comprehensive audit trail
- Tamper-proof logging

---

## Incident Response

### Security Incident Detected

**Agent Actions**:
1. 🚨 Alert security team immediately
2. 📝 Log all evidence
3. 🔒 Isolate affected resources (if safe)
4. 🛡️ Preserve forensic data
5. 📧 Send detailed incident report

**What Agent Does NOT Do**:
- ❌ Delete logs (evidence)
- ❌ Modify affected systems
- ❌ Execute remediation without approval
- ❌ Alert the attacker

**Example Alert**:
```
SECURITY INCIDENT DETECTED

Severity: CRITICAL
Incident ID: SEC-2026-001
Time: 2026-06-12 15:30:00 UTC

ISSUE:
Unauthorized API access detected from unknown IP

EVIDENCE:
- Source IP: 192.168.1.100
- Target: /api/admin/users
- Method: GET
- Response: 200 OK
- User-Agent: curl/7.64.1

IMMEDIATE ACTIONS:
1. Review access logs
2. Check if credentials compromised
3. Rotate API keys
4. Block suspicious IP
5. Conduct security audit

FORENSICS PRESERVED:
- Full request/response logs
- Network packet capture
- System audit logs

Contact: security-team@company.com
```

### Compliance Violation

**Example**:
```
COMPLIANCE VIOLATION

Framework: PCI-DSS
Requirement: 8.7 - Database Access Restrictions
Severity: HIGH

VIOLATION:
Database credentials exposed in environment variables

AFFECTED RESOURCES:
- deployment/payment-service (production)

REMEDIATION STEPS:
1. Rotate database credentials immediately
2. Move credentials to Secrets Manager
3. Update deployment to use secret references
4. Audit all other deployments
5. Update runbooks

DEADLINE: 24 hours
```

---

## Audit & Monitoring

### Audit Trail

Every action logged:
```json
{
  "timestamp": "2026-06-12T15:30:00Z",
  "incident_id": "INC-123",
  "action": "dangerous_operation_blocked",
  "operation": "kubectl delete pod",
  "reason": "Deletion is destructive",
  "severity": "HIGH",
  "agent_decision": "Blocked and sent email notification",
  "email_sent_to": ["sre-team@company.com"],
  "context": {
    "namespace": "production",
    "pod": "api-service-xyz",
    "reason_for_deletion": "CrashLoopBackOff"
  },
  "recommended_action": "Fix underlying issue instead of deleting",
  "manual_commands": [
    "kubectl logs api-service-xyz -n production",
    "kubectl describe pod api-service-xyz -n production"
  ]
}
```

### Metrics

Monitor agent behavior:
```yaml
agent_security_findings_total: 42
agent_blocked_operations_total: 5
agent_compliance_violations_total: 3
agent_critical_alerts_total: 2

# Per severity
agent_findings_by_severity{severity="CRITICAL"}: 1
agent_findings_by_severity{severity="HIGH"}: 8
agent_findings_by_severity{severity="MEDIUM"}: 18
agent_findings_by_severity{severity="LOW"}: 15
```

### Alerting Rules

```yaml
groups:
  - name: agent_security
    rules:
      - alert: HighSecurityFindings
        expr: increase(agent_security_findings_total{severity="CRITICAL"}[1h]) > 0
        annotations:
          summary: Critical security findings detected
      
      - alert: BlockedDangerousOperations
        expr: increase(agent_blocked_operations_total[1h]) > 5
        annotations:
          summary: Multiple dangerous operations blocked
      
      - alert: ComplianceViolations
        expr: agent_compliance_violations_total > 0
        annotations:
          summary: Compliance violations detected
```

---

## Security Checklist

### Before Deploying Agent

- [ ] Review SECURITY_POLICY.md
- [ ] Configure email notifications
- [ ] Set AUTO_APPLY=false
- [ ] Enable security scanning
- [ ] Configure compliance frameworks
- [ ] Set up RBAC with minimal permissions
- [ ] Enable audit logging
- [ ] Configure alert routing
- [ ] Test emergency stop
- [ ] Document runbooks

### Weekly Review

- [ ] Review audit logs
- [ ] Check blocked operations
- [ ] Review security findings
- [ ] Verify compliance status
- [ ] Update allowed namespaces
- [ ] Rotate credentials
- [ ] Test alert channels
- [ ] Update documentation

### Monthly Review

- [ ] Security audit of agent permissions
- [ ] Review all approved operations
- [ ] Update security scanning rules
- [ ] Compliance framework review
- [ ] Incident response drill
- [ ] Update threat models
- [ ] Review and update runbooks

---

## Emergency Procedures

### Emergency Stop

```bash
# Stop all agent operations immediately
curl -X POST https://agent.company.com/emergency-stop \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Or via environment
export AGENT_EMERGENCY_STOP=true
```

### Incident Response

```bash
# 1. Isolate the agent
kubectl scale deployment devops-agent --replicas=0

# 2. Preserve logs
kubectl logs deployment/devops-agent > agent-forensics.log

# 3. Review audit trail
curl -H "Authorization: Bearer $API_TOKEN" https://agent.company.com/audit > audit-trail.json

# 4. Investigate
grep "CRITICAL" audit-trail.json
grep "blocked" audit-trail.json

# 5. Restore safely
# Review findings, fix issues, then:
kubectl scale deployment devops-agent --replicas=1
```

---

## Support & Resources

- Security Policy: [SECURITY_POLICY.md](SECURITY_POLICY.md)
- Architecture: [ARCHITECTURE.md](ARCHITECTURE.md)
- Incident Reports: security@yourcompany.com
- Emergency Contact: +1-XXX-XXX-XXXX

---

**Remember: Security is everyone's responsibility. The agent is a tool to help, not a replacement for security best practices.**
