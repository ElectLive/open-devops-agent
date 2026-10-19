# Edge Middleware

Thin connector between **your network** and the **central open-source DevOps AI Agent**.

You deploy this small service near your servers/CI — **not** the full agent — and it:

1. **Forwards** alerts / incidents to the central agent (`POST /forward`)
2. Optionally **runs allowlisted local commands** when the agent cannot SSH in (`POST /exec`)

```text
Alertmanager / GitLab / your apps
              │
              ▼
     middleware (this folder)     ← you deploy here
              │
              ▼
     central agent (open-source)  ← one deployment
              │
              ▼
     Slack / PRs / cloud APIs
```

## Quick start

```bash
cd middleware
cp .env.example .env
# set AGENT_BASE_URL, AGENT_WEBHOOK_SECRET, MIDDLEWARE_AUTH_TOKEN

pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8080
```

Docker:

```bash
docker build -t devops-agent-middleware .
docker run --env-file .env -p 8080:8080 devops-agent-middleware
```

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness |
| `POST` | `/forward` or `/webhook` or `/webhook/{source}` | Forward JSON incident to central agent |
| `POST` | `/exec` | Optional allowlisted local command (off by default) |

Auth (required by default via `MIDDLEWARE_AUTH_TOKEN`):

```http
Authorization: Bearer <token>
# or
X-Middleware-Token: <token>
```

### Forward example

```bash
curl -X POST http://localhost:8080/forward \
  -H "Authorization: Bearer $MIDDLEWARE_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "server",
    "host": "ubuntu@10.0.1.50",
    "description": "Disk full on app host",
    "raw_logs": "df -h shows / at 96%"
  }'
```

Point Alertmanager / GitLab at `https://middleware.internal/forward` (or `/webhook/gitlab`) instead of the central agent if the agent is not reachable from that network.

### Exec example (optional)

```bash
# On middleware host
MIDDLEWARE_EXEC_ENABLED=true

# Central agent (or you) calls back:
curl -X POST http://middleware.internal:8080/exec \
  -H "Authorization: Bearer $MIDDLEWARE_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"docker ps"}'
```

Destructive commands (`rm -rf`, pipe-to-shell, etc.) are always blocked.

## Env

See [`.env.example`](.env.example).

| Variable | Required | Meaning |
|----------|----------|---------|
| `AGENT_BASE_URL` | yes | Central agent base URL |
| `AGENT_WEBHOOK_SECRET` | recommended | Same as agent `WEBHOOK_SECRET` |
| `MIDDLEWARE_AUTH_TOKEN` | yes | Protects this middleware (required unless `MIDDLEWARE_ALLOW_UNAUTHENTICATED=true`) |
| `MIDDLEWARE_ALLOW_UNAUTHENTICATED` | no | Set `true` to allow unauthenticated `/forward` when token unset (default `false`) |
| `MIDDLEWARE_TRUST_CALLER_ORG_ID` | no | Set `true` or comma-separated allowlist to trust caller `X-Org-ID` (default `false`) |
| `ORG_ID` | no | Default org on forwarded events |
| `MIDDLEWARE_EXEC_ENABLED` | no | Enable `/exec` (default `false`, requires `MIDDLEWARE_AUTH_TOKEN`) |

## Security

- Do **not** put `ANTHROPIC_API_KEY` here — only on the central agent
- Keep `MIDDLEWARE_EXEC_ENABLED=false` unless the agent cannot SSH
- Run on a private network; expose only to Alertmanager / agent
- Rotate `MIDDLEWARE_AUTH_TOKEN` and `AGENT_WEBHOOK_SECRET`

## Related

- [Centralized deployment](../docs/CENTRALIZED_DEPLOYMENT.md) — full agent once
- [API reference](../docs/API_REFERENCE.md) — `/webhook/manual` payload shape
