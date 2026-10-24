# Centralized Agent Deployment

How the DevOps AI Agent works when deployed on **one central server** (not on every EC2/K8s node).

## Architecture

```text
                    ┌─────────────────────────┐
  Alertmanager ────▶│                         │
  GitHub webhooks ─▶│   Central Agent Server  │────▶ Slack / Jira / Email
  Manual triggers ─▶│   (FastAPI + Claude)    │
                    │                         │
                    └───────────┬─────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
      SSH ──▶ EC2 VMs     K8s API ──▶ Pods    Cloud APIs ──▶ AWS/GCP/Azure
      (Docker, nginx)     (EKS/GKE/AKS)       (EC2, RDS, etc.)
```

**One agent** handles many targets via APIs and SSH — you do **not** need an agent on every server.

---

## How each target type is reached

| Incident type | Central agent connects via | Config needed |
|---------------|---------------------------|---------------|
| **server** / Docker on EC2 | **SSH** (`host` in webhook) | SSH key, `user@ip` in context |
| **k8s** | **Kubernetes API** | `KUBECONFIG` or in-cluster ServiceAccount |
| **cicd** | **GitHub/GitLab/Jenkins APIs** | `GITHUB_TOKEN`, `GITLAB_TOKEN`, etc. |
| **cloud_aws** | **AWS API** (boto3) | IAM role or `AWS_ACCESS_KEY_ID` on agent server |
| **cloud_gcp** | **GCP API** | `GOOGLE_APPLICATION_CREDENTIALS` |
| **cloud_azure** | **Azure API** | `AZURE_*` credentials or managed identity |
| **argocd** | **ArgoCD API** | `ARGOCD_SERVER_URL`, `ARGOCD_AUTH_TOKEN` |

---

## Remote server / Docker (SSH)

When the agent runs on a **different server** than your broken Docker app:

### 1. SSH access from agent → target

On the **central agent server**:

```bash
# Generate key (if needed)
ssh-keygen -t ed25519 -f ~/.ssh/agent_key -N ""

# Copy to target EC2
ssh-copy-id -i ~/.ssh/agent_key.pub ubuntu@10.0.1.50

# Test passwordless SSH
ssh -i ~/.ssh/agent_key ubuntu@10.0.1.50 'docker ps'
```

Configure SSH for the agent user:

```bash
# ~/.ssh/config on agent server
Host ec2-app-*
    User ubuntu
    IdentityFile ~/.ssh/agent_key
    UserKnownHostsFile ~/.ssh/known_hosts
    StrictHostKeyChecking yes
```

> **Security note:** The agent defaults to OpenSSH's strict host-key verification.
> Remote collection will fail if the target host is not present in `known_hosts`.
> Populate `known_hosts` before deploying:
>
> ```bash
> ssh-keyscan -H <remote-host> >> ~/.ssh/known_hosts
> ```

### 2. Trigger with `host` in webhook

```bash
curl -X POST http://central-agent.company.com:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: acme-corp" \
  -d '{
    "type": "server",
    "host": "ubuntu@10.0.1.50",
    "description": "Docker container broken-app keeps restarting",
    "service": "broken-app",
    "node": "10.0.1.50"
  }'
```

The agent will:
1. **Collect** remote diagnostics via SSH (`server_data` from target host)
2. **Run tools** with `run_shell_command` + `host` → `ssh ubuntu@10.0.1.50 'docker logs ...'`

Use format `user@hostname` or `user@ip` for `host`.

### 3. Alertmanager auto-pass host

Add labels to Prometheus alerts:

```yaml
labels:
  instance: "10.0.1.50"
  host: "ubuntu@10.0.1.50"
  org_id: "acme-corp"
```

Alertmanager webhook forwards `node`, `host`, and `labels` into context automatically.

---

## Kubernetes (central agent outside cluster)

```bash
# On central agent server — point to cluster API
export KUBECONFIG=/etc/devops-agent/kubeconfig-prod.yaml

# Or mount kubeconfig in Docker/K8s deployment
```

Agent uses `kubectl` / K8s Python client against the API — **no SSH to nodes** needed.

```bash
curl -X POST http://central-agent:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "k8s",
    "namespace": "production",
    "pod": "api-xyz"
  }'
```

---

## AWS EC2 (API instead of SSH)

Alternative to SSH — use cloud collector:

```bash
curl -X POST http://central-agent:8000/webhook/manual \
  -H "Content-Type: application/json" \
  -d '{
    "type": "cloud_aws",
    "resource_type": "ec2",
    "resource_id": "i-0abc123def456",
    "params": {"region": "us-east-1"}
  }'
```

Good for instance status/metrics. For **Docker logs on the instance**, SSH is still required.

---

## Central agent `.env` checklist

```bash
# Core
ANTHROPIC_API_KEY=...
ORG_ID=acme-corp
STORAGE_PROVIDER=s3          # shared audit across replicas
AUTO_APPLY=true              # or false + Slack approval

# K8s (if used)
KUBECONFIG=/etc/devops-agent/kubeconfig

# Cloud APIs (if used)
AWS_REGION=us-east-1
# IAM role on agent EC2/instance profile recommended

# CI/CD
GITHUB_TOKEN=...
GITLAB_TOKEN=...

# SSH: ensure agent OS user has keys in ~/.ssh/
# SSH_KNOWN_HOSTS=/etc/devops-agent/known_hosts
# SSH_REMOTE_USER=ubuntu
```

---

## Deploy central agent (options)

### Docker on dedicated VM

```bash
docker run -d \
  --name devops-agent \
  -p 8000:8000 \
  -v ~/.kube:/home/appuser/.kube:ro \
  -v ~/.ssh:/home/appuser/.ssh:ro \
  -v /path/to/known_hosts:/etc/devops-agent/known_hosts:ro \
  -v agent-data:/data \
  --env-file .env \
  -e SSH_KNOWN_HOSTS=/etc/devops-agent/known_hosts \
  devops-ai-agent:latest
```

### Kubernetes (one deployment, many clusters)

```yaml
# Mount kubeconfig secret per cluster or use in-cluster SA for local cluster
volumes:
  - name: kubeconfig
    secret:
      secretName: agent-kubeconfig-prod
  - name: ssh-keys
    secret:
      secretName: agent-ssh-keys
      defaultMode: 0600
  - name: ssh-known-hosts
    configMap:
      name: agent-ssh-known-hosts
```

### HA: multiple replicas + shared storage

```bash
STORAGE_PROVIDER=s3
STORAGE_BUCKET=devops-agent-prod
# Queue worker recovers stale incidents on any replica
```

---

## EC2 Docker test — centralized version

| Step | Central server | Target EC2 |
|------|----------------|------------|
| 1 | Deploy agent | Run `ec2-docker-test-setup.sh` (broken container) |
| 2 | Configure SSH key → target | Allow port 22 from agent SG |
| 3 | Trigger webhook with `"host": "ubuntu@TARGET_IP"` | — |
| 4 | Poll `/audit` on central agent | Container fixed via SSH |

```bash
# Central agent URL
AGENT=http://agent.internal:8000
TARGET=ubuntu@10.0.1.50

curl -X POST $AGENT/webhook/manual \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: acme-corp" \
  -d "{\"type\":\"server\",\"host\":\"$TARGET\",\"service\":\"broken-app\",\"description\":\"Docker crash loop on EC2\"}"

curl -H "Authorization: Bearer $API_TOKEN" "$AGENT/audit?org_id=acme-corp"
```

---

## Limitations

| Scenario | Works? | Notes |
|----------|--------|-------|
| Remote Docker via SSH | ✅ | Needs `host` + SSH keys |
| Remote server without SSH | ❌ | Use monitoring to push `raw_logs` in webhook |
| Private EC2 (no public IP) | ✅ | Agent in same VPC, SSH private IP |
| Air-gapped targets | Partial | Forward logs via webhook `raw_logs` field |
| Edit remote files (compose.yml) | ⚠️ | Needs approval; agent may suggest commands not auto-run |

---

## Security recommendations

- Run agent in a **private subnet**; expose `:8000` only via internal LB or VPN
- Use **dedicated SSH key** per agent with `sudo` limited to docker/systemctl
- **IAM roles** instead of long-lived cloud keys
- Rotate `WEBHOOK_SECRET`, API tokens
- `AUTO_APPLY=false` in production → Slack approval for fixes

---

## Edge middleware (optional)

If the central agent is not reachable from Alertmanager/CI (or cannot SSH into a VPC), deploy the thin connector in [`middleware/`](../middleware/):

```text
alerts → middleware → central agent
agent  → middleware /exec → allowlisted local commands (optional)
```

See [`middleware/README.md`](../middleware/README.md). You still run the open-source agent **once**; hosts only need the middleware.

---

## Related

- [E2E EC2 Docker Test](E2E_EC2_DOCKER_TEST.md) — same-host variant
- [Deployment](DEPLOYMENT.md)
- [Organizational Guide](ORGANIZATIONAL_GUIDE.md)
- [API Reference](API_REFERENCE.md)
- [Edge middleware](../middleware/README.md)
