# N8N SOAR Integration

Automated Security Orchestration, Automation and Response (SOAR) using [N8N](https://n8n.io/) workflows integrated with Grafana alerting and Wazuh.

## Architecture Overview

```
┌─────────────┐    webhook     ┌───────────────────────────────┐
│   Grafana    │──────────────►│  Grafana Alert Router (N8N)   │
│  Alerting    │  POST /webhook│  Switch firing/resolved →     │
│  (8 rules)   │  /grafana-    │  Discord embed per status     │
└─────────────┘  alerts        └───────────────────────────────┘

┌─────────────┐    webhook     ┌───────────────────────────────┐
│   Wazuh      │──────────────►│  Wazuh Alert Triage (N8N)     │
│   Manager    │  POST /webhook│  Severity router → Discord +  │
│ (integratord)│  /wazuh-alerts│  Attack categorizer (brute    │
└─────────────┘                │  force, FIM, vulnerability)   │
                               └───────────────────────────────┘

┌─────────────┐    webhook     ┌───────────────────────────────┐
│   Grafana    │──────────────►│  CrowdSec Alert Enrichment    │
│  Alerting    │  POST /webhook│  (N8N) Query OpenSearch for   │
│ source=      │  /crowdsec-   │  recent bans → enriched       │
│  crowdsec    │  alerts       │  Discord embed with IPs       │
└─────────────┘                └───────────────────────────────┘
```

## Workflows

### Grafana Alert Router (`n8n/grafana-alert-router.json`)

Routes Grafana alert notifications to Discord with status-appropriate formatting:

- **Grafana Webhook** → receives POST from Grafana contact point
- **Alert Status** (Switch node) → routes `firing` vs `resolved`
- **Discord — Firing** → red embed with severity, instance, description
- **Discord — Resolved** → green embed with resolution timestamp

### CrowdSec Alert Enrichment (`n8n/crowdsec-alert-enrichment.json`)

Receives CrowdSec alerts from Grafana and enriches them with live OpenSearch data before sending to Discord:

- **CrowdSec Webhook** → receives POST from Grafana contact point (`/crowdsec-alerts`)
- **Alert Status** (Switch node) → routes `firing` vs `resolved`
- **Query OpenSearch Bans** → queries `crowdsec-events-*` for recent ban decisions (last 1h), aggregates banned IPs, programs, and source hosts
- **Enrich Alert Data** (Code node) → extracts IP addresses, total bans, program breakdown from OpenSearch response
- **Discord — CrowdSec Firing** → orange embed with banned IPs, total bans, active programs, source hosts
- **Discord — CrowdSec Resolved** → green embed with resolution timestamp

**Placeholders to replace:**
- `OPENSEARCH_URL` → your OpenSearch URL (e.g., `http://opensearch-hot:9200` for Docker network)
- `YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN` → Discord webhook credentials
- `YOUR_DISCORD_USER_ID` → your Discord user ID for mentions

### Wazuh Alert Triage (`n8n/wazuh-alert-triage.json`)

Routes Wazuh alerts by severity level with attack-type categorization:

- **Wazuh Webhook** → receives POST from Wazuh `integratord`
- **Severity Router** (Switch node):
  - Level 12+ → **Discord Critical** (immediate notification)
  - Level 10–11 → **Discord High** (immediate notification)
  - Level 7–9 → **Log Medium** (logged, no Discord)
  - Level <7 → **Log Low** (logged, no Discord)
- **Attack Categorizer** (Switch node) → classifies rule groups:
  - Brute force / authentication failures → Discord alert
  - File integrity (syscheck) → Discord alert
  - Vulnerability detection → Discord alert

## Grafana Alert Rules

The deployment creates 7 alert rules across 4 rule groups:

| Rule | Group | Severity | Condition |
|------|-------|----------|-----------|
| Wazuh Agent Disconnected | SIEM — Wazuh | Critical | rule.id 503, 5m evaluation |
| High-Severity Alert Burst | SIEM — Wazuh | Critical | >50 alerts with level ≥10 in 5m |
| Authentication Failure Burst | SIEM — Wazuh | Critical | >20 auth failures in 5m |
| Critical File Integrity Change | SIEM — Wazuh | Warning | FIM syscheck level ≥7 in 10m |
| Suricata Critical Alert | SIEM — IDS | Critical | severity 1 alerts in 5m |
| pfSense Firewall Block Surge | SIEM — Firewall | Warning | >500 blocks in 5m |
| Docker Container Restart Loop | SIEM — Docker | Warning | 3+ restarts in 10m |
| CrowdSec Ban Decision Surge | SIEM — CrowdSec | Critical | Ban decisions surging in 5m |

## Prerequisites

1. **N8N container running** on the SIEM Docker network (see `docker-compose.yml`)
2. **Grafana** with datasources configured (Wazuh, Suricata, Prometheus)
3. **Discord webhook URL** — see [Creating a Discord Webhook](#creating-a-discord-webhook)
4. **Python 3** on the deployment machine (for the Python deploy scripts)
5. **SSH access** to the SIEM server (for the bash deploy script)

## Environment Variables

All scripts read configuration from environment variables. Create a `.env` file (already in `.gitignore`) or export them in your shell.

### N8N Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `N8N_BASE` | N8N internal URL (Docker bridge IP) | `http://172.20.0.16:80` |
| `N8N_API_KEY` | N8N public API key (Settings → API) | `eyJhbGci...` |
| `N8N_EMAIL` | N8N login email (for internal API) | `admin@example.com` |
| `N8N_PASSWORD` | N8N login password | `your-password` |

### Discord Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `DISCORD_WEBHOOK_URL` | Full Discord webhook URL | `https://discord.com/api/webhooks/ID/TOKEN` |
| `DISCORD_MENTION` | User or role mention for alerts | `<@USER_ID>` or `<@&ROLE_ID>` |

### Grafana Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `GRAFANA_URL` | Grafana base URL | `http://localhost:3000` |
| `GRAFANA_USER` | Grafana admin username | `admin` |
| `GRAFANA_PASS` | Grafana admin password | `your-password` |
| `ALERT_FOLDER_UID` | Grafana folder UID for alert rules | `abc123def456` |
| `DS_WAZUH` | Wazuh datasource UID | `P75BB31...` |
| `DS_SURICATA` | Suricata datasource UID | `fff2ee...` |
| `DS_PROMETHEUS` | Prometheus datasource UID | `PBFA97...` |

### SSH Configuration (bash script only)

| Variable | Description | Default |
|----------|-------------|---------|
| `SIEM_USER` | SSH username for SIEM server | `siem` |
| First argument | SIEM server IP | `10.0.0.100` |

## Finding Your Configuration Values

### N8N API Key

1. Open the N8N web UI
2. Go to **Settings** → **API** (or **n8n API** in newer versions)
3. Click **Create an API key**
4. Copy the JWT token — this is your `N8N_API_KEY`

### Grafana Datasource UIDs

1. Open Grafana → **Connections** → **Data sources**
2. Click on each datasource (e.g., "Wazuh Alerts")
3. The UID is in the URL: `grafana.example.com/connections/datasources/edit/P75BB31EF98597818`
4. Copy the last path segment — that's the UID

Alternatively, query the API:
```bash
curl -s -u admin:password http://localhost:3000/api/datasources | python3 -c "
import sys, json
for ds in json.load(sys.stdin):
    print(f'{ds[\"name\"]:30s} UID: {ds[\"uid\"]}')
"
```

### Grafana Alert Folder UID

1. Create a folder in Grafana: **Dashboards** → **New** → **New Folder** → name it "SIEM Alerts"
2. Navigate into the folder
3. The UID is in the URL: `grafana.example.com/dashboards/f/abc123def456/siem-alerts`
4. Copy the UID segment — that's your `ALERT_FOLDER_UID`

### Creating a Discord Webhook

1. Open Discord → right-click your target channel → **Edit Channel**
2. Go to **Integrations** → **Webhooks** → **New Webhook**
3. Name it (e.g., "SIEM Alerts"), optionally set an avatar
4. Click **Copy Webhook URL** — this is your `DISCORD_WEBHOOK_URL`
5. The URL format is: `https://discord.com/api/webhooks/{WEBHOOK_ID}/{WEBHOOK_TOKEN}`

### Discord User/Role ID for Mentions

1. Enable **Developer Mode** in Discord: User Settings → App Settings → Advanced → Developer Mode
2. Right-click your username → **Copy User ID** → use as `<@USER_ID>`
3. For role mentions: right-click the role → **Copy Role ID** → use as `<@&ROLE_ID>`

## Deployment

There are three deployment scripts, depending on your needs:

### Option A: Full Automated Deploy (Bash)

Deploys both N8N workflows AND Grafana alert rules in one pass via SSH:

```bash
# Set required variables
export N8N_API_KEY="your-n8n-api-key"
export SIEM_USER="your-ssh-user"
export ALERT_FOLDER_UID="your-folder-uid"

# Deploy everything
./scripts/deploy-n8n-soar.sh 10.0.0.100
```

This script:
1. Creates/updates both N8N workflows via the public API
2. Activates the workflows
3. Creates the N8N-SOAR webhook contact point in Grafana
4. Creates all 7 Grafana alert rules (idempotent — skips existing)
5. Updates the Grafana notification policy to route SIEM alerts to N8N

### Option B: Deploy Grafana Router Only (Python)

For deploying just the Grafana alert router workflow to N8N. This script uses a two-step strategy to work around an N8N public API validation bug with Switch V3 nodes:

```bash
# Set environment variables
export N8N_BASE="http://172.20.0.16:80"
export N8N_API_KEY="your-n8n-api-key"
export N8N_EMAIL="admin@example.com"
export N8N_PASSWORD="your-password"
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/ID/TOKEN"
export DISCORD_MENTION="<@YOUR_USER_ID>"

# Deploy via SSH pipe (no file copy needed)
ssh user@siem-server 'python3 -' < scripts/deploy-n8n-grafana-router.py
```

### Option C: Deploy Grafana Alert Rules Only (Python)

For deploying just the 7 Grafana SIEM alert rules:

```bash
export GRAFANA_URL="http://localhost:3000"
export GRAFANA_USER="admin"
export GRAFANA_PASS="your-grafana-password"
export ALERT_FOLDER_UID="your-folder-uid"
export DS_WAZUH="your-wazuh-ds-uid"
export DS_SURICATA="your-suricata-ds-uid"
export DS_PROMETHEUS="your-prometheus-ds-uid"

ssh user@siem-server 'python3 -' < scripts/deploy-grafana-alerts.py
```

### Option D: Manual Import via N8N UI

If you prefer not to use the deploy scripts:

1. Open the N8N web UI
2. Go to **Workflows** → **Add Workflow** → **Import from File**
3. Import `n8n/grafana-alert-router.json`
4. Import `n8n/wazuh-alert-triage.json`
5. **Edit each workflow** — find all HTTP Request nodes and replace:
   - `https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN` → your actual Discord webhook URL
   - `<@YOUR_DISCORD_USER_ID>` → your actual Discord mention
6. **Activate** both workflows (toggle in top-right)
7. Note the webhook URLs shown in each Webhook node — use these for Grafana/Wazuh configuration

## Post-Deployment Configuration

### Connect Grafana to N8N

After deploying the Grafana Alert Router workflow:

1. In Grafana, go to **Alerting** → **Contact points** → **Add contact point**
2. Name: `N8N-SOAR`
3. Type: **Webhook**
4. URL: `http://n8n:5678/webhook/grafana-alerts` (use Docker service name if on the same network, or the N8N container IP)
5. HTTP Method: `POST`
6. Save and test

### Connect Wazuh to N8N

Configure Wazuh's `integratord` to send alerts to the N8N webhook:

1. Edit `/var/ossec/etc/ossec.conf` on the Wazuh manager:

```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>http://N8N_IP:5678/webhook/wazuh-alerts</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

2. Restart the Wazuh manager: `systemctl restart wazuh-manager`

Replace `N8N_IP` with your N8N container's IP address on the Docker network.

## Important: Webhook Body Wrapping

N8N's Webhook node wraps incoming POST data in a structured envelope:

```json
{
  "headers": { ... },
  "params": {},
  "query": {},
  "body": {
    // ← your actual POST payload is here
  },
  "webhookUrl": "...",
  "executionMode": "production"
}
```

**All expressions in the workflow must reference `$json.body.field`, not `$json.field`.**

For example:
- Grafana alert status: `{{ $json.body.status }}` (not `{{ $json.status }}`)
- Wazuh rule level: `{{ $json.body.rule.level }}` (not `{{ $json.rule.level }}`)

The included workflow templates already use the correct `$json.body.` prefix. If you modify expressions or create new nodes, remember this wrapping behavior.

## N8N Switch Node V3 Schema

The workflows use N8N Switch node v3.2, which has specific schema requirements that differ from older versions. The deploy scripts handle this automatically, but if you're editing workflows manually:

```json
{
  "parameters": {
    "rules": {
      "values": [
        {
          "conditions": {
            "options": { "caseSensitive": true, "leftValue": "", "typeValidation": "strict" },
            "conditions": [
              {
                "leftValue": "={{ $json.body.status }}",
                "rightValue": "firing",
                "operator": { "type": "string", "operation": "equals" }
              }
            ],
            "combinator": "and"
          },
          "renameOutput": true,
          "outputKey": "Firing"
        }
      ]
    },
    "options": {
      "fallbackOutput": { "type": "extra", "outputIndex": 2 }
    }
  },
  "type": "n8n-nodes-base.switch",
  "typeVersion": 3.2
}
```

Key requirements for Switch V3:
- Rules go under `rules.values[]` (not `rules.rules[]` as in older docs)
- Each rule needs `renameOutput: true` and `outputKey: "label"` for named outputs
- Fallback output uses `options.fallbackOutput` (not `options.default`)
- The N8N **public API has a validation bug** with Switch V3 — the `deploy-n8n-grafana-router.py` script works around this by creating a simple workflow first, then patching via the internal REST API

## Testing

### Test Grafana Alert Router

```bash
# Send a test firing alert
curl -X POST http://N8N_IP:5678/webhook/grafana-alerts \
  -H "Content-Type: application/json" \
  -d '{
    "status": "firing",
    "alerts": [{
      "status": "firing",
      "labels": {
        "alertname": "Test Alert",
        "severity": "warning",
        "instance": "test-host:9090"
      },
      "annotations": {
        "summary": "This is a test alert",
        "description": "Testing the Grafana alert router workflow"
      },
      "startsAt": "2025-01-01T00:00:00Z"
    }]
  }'
```

### Test Wazuh Alert Triage

```bash
# Send a test critical alert (level 12)
curl -X POST http://N8N_IP:5678/webhook/wazuh-alerts \
  -H "Content-Type: application/json" \
  -d '{
    "rule": {
      "level": 12,
      "description": "Test critical alert",
      "id": "5710",
      "groups": ["authentication_failures"]
    },
    "agent": {
      "name": "test-agent",
      "id": "001"
    },
    "full_log": "Test log entry for SOAR validation"
  }'
```

### Verify Execution

1. Check N8N UI → **Executions** — both workflows should show successful runs
2. Check your Discord channel — you should see formatted alert embeds
3. If no Discord message appears, check the execution details for HTTP errors

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| Webhook returns 404 | Workflow not activated | Activate workflow in N8N UI |
| Discord returns 400 | Malformed embed JSON | Check N8N execution → HTTP Request node → response body |
| `$json.body` is undefined | Direct API call without webhook wrapping | Ensure the POST hits the `/webhook/` path, not the API directly |
| Switch node "Could not find property option" | Using `rules.rules` instead of `rules.values` | Re-import the provided JSON templates (they use correct V3 schema) |
| Grafana alerts not reaching N8N | Contact point misconfigured | Verify N8N contact point URL and test with Grafana's "Test" button |
| Wazuh alerts not reaching N8N | `integratord` not configured | Check `ossec.conf` integration block and restart wazuh-manager |

## File Reference

| File | Purpose |
|------|---------|
| `n8n/grafana-alert-router.json` | N8N workflow template — Grafana alerts → Discord |
| `n8n/wazuh-alert-triage.json` | N8N workflow template — Wazuh alerts → severity triage → Discord |
| `scripts/deploy-n8n-soar.sh` | Full deployment: workflows + alert rules + contact points |
| `scripts/deploy-n8n-grafana-router.py` | Python script: deploy Grafana router with Switch V3 workaround |
| `scripts/deploy-grafana-alerts.py` | Python script: deploy 7 Grafana SIEM alert rules |
| `.env.example` | Template for all environment variables |
