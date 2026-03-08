# JumpCloud IdP Integration

Ingest JumpCloud Directory Insights events into the SIEM stack via Wazuh for
centralized identity-and-access monitoring.

---

## Architecture

```
JumpCloud API  ──►  jumpcloud-wazuh-bridge (Python)
                         │  writes JSONL
                         ▼
                   /var/log/jumpcloud_events.jsonl
                         │
                   Wazuh <localfile> (json)
                         │
                   Wazuh decoders + rules
                         │  120600–120681
                         ▼
                   OpenSearch (wazuh-alerts-4.x-*)
                         │
                   Grafana dashboard
```

## Prerequisites

| Component | Version | Notes |
|-----------|---------|-------|
| Python    | 3.9+    | Bridge poller |
| Wazuh manager | 4.x | Reads the JSONL via `<localfile>` |
| JumpCloud API key | Read-only | Directory Insights access only |
| Doppler CLI (recommended) | Latest | Secrets management |

### JumpCloud API Key

1. **JumpCloud Admin Console → API Settings** — create a read-only API key
   with Directory Insights access.
2. Store it in Doppler (recommended) or export as `JUMPCLOUD_API_KEY`.

---

## Installation

### 1. Deploy the Bridge

```bash
cd /opt/jumpcloud-wazuh-bridge   # or wherever you prefer
git clone <your-fork> .
pip install -r requirements.txt
```

### 2. Configure Secrets

**Option A — Doppler (recommended for production):**

```bash
doppler setup          # select your project + config
doppler run -- python -m jumpcloud_wazuh_bridge --once   # test
```

Required Doppler secrets:

| Key | Description |
|-----|-------------|
| `JUMPCLOUD_API_KEY` | Read-only Directory Insights key |
| `JUMPCLOUD_ORG_ID`  | Multi-tenant orgs only (optional) |

**Option B — Environment variables:**

```bash
export JUMPCLOUD_API_KEY=your-key
export JUMPCLOUD_ORG_ID=             # optional
export JUMPCLOUD_POLL_SECONDS=300
export JUMPCLOUD_SERVICES=all
export JUMPCLOUD_OUTPUT=/var/log/jumpcloud_events.jsonl
python -m jumpcloud_wazuh_bridge --once
```

### 3. Configure Wazuh

Copy the decoder and rule files to the Wazuh manager:

```bash
# On the Wazuh manager host (or into the Wazuh Docker volume)
cp wazuh/jumpcloud_decoders.xml /var/ossec/etc/decoders/jumpcloud_decoders.xml
cp wazuh/jumpcloud_rules.xml   /var/ossec/etc/rules/jumpcloud_rules.xml
```

Add a `<localfile>` block to `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/jumpcloud_events.jsonl</location>
  <label key="source">jumpcloud</label>
</localfile>
```

Restart the Wazuh manager:

```bash
systemctl restart wazuh-manager
# or inside Docker: docker restart siem-wazuh-manager
```

### 4. Deploy the Grafana Dashboard

Import `dashboards/jumpcloud_security.json` via the Grafana UI or API.

### 5. Run Continuously

**Systemd (recommended):**

```ini
[Unit]
Description=JumpCloud Wazuh Bridge
After=network.target

[Service]
ExecStart=/usr/bin/python3 -m jumpcloud_wazuh_bridge
WorkingDirectory=/opt/jumpcloud-wazuh-bridge
Restart=on-failure
RestartSec=30
User=jumpcloud
Environment=JUMPCLOUD_API_KEY=changeme

[Install]
WantedBy=multi-user.target
```

**Or with Doppler:**

```ini
ExecStart=/usr/bin/doppler run -- python3 -m jumpcloud_wazuh_bridge
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `JUMPCLOUD_API_KEY` | *(required)* | Read-only API key |
| `JUMPCLOUD_BASE_URL` | `https://api.jumpcloud.com` | API base URL |
| `JUMPCLOUD_ORG_ID` | *(empty)* | Multi-tenant org ID |
| `JUMPCLOUD_LOOKBACK_MINUTES` | `10` | Initial lookback window |
| `JUMPCLOUD_POLL_SECONDS` | `300` | Polling interval |
| `JUMPCLOUD_OUTPUT` | `/var/log/jumpcloud_events.jsonl` | JSONL output path |
| `JUMPCLOUD_STATE` | `/var/lib/jumpcloud_bridge/cursor.json` | Cursor state file |
| `JUMPCLOUD_SERVICES` | `all` | Comma-separated: directory,sso,radius,ldap,systems,software,mdm,alerts,all |
| `JUMPCLOUD_PAGE_LIMIT` | `1000` | Events per API page (max 10000) |

---

## Wazuh Rule Coverage

Rules occupy IDs **120600–120681** in group `jumpcloud`.

| ID Range | Category | Examples |
|----------|----------|---------|
| 120600 | Catch-all | Any JumpCloud event |
| 120601–120606 | Portal Auth | Admin/user login success, failure, brute-force |
| 120610–120611 | SSO | SSO auth success/failure |
| 120615–120616 | RADIUS | RADIUS auth success/failure |
| 120620–120622 | LDAP | Bind success/failure, search events |
| 120625–120627 | System Login | Agent login success/failure, lockout |
| 120630–120636 | User Lifecycle | Create, delete, update, suspend, activate, password |
| 120640–120643 | Admin Lifecycle | Create, delete, update, lockout |
| 120650–120656 | Groups & Policies | Group/policy CRUD, associations, conditional access |
| 120660–120662 | MFA | TOTP enroll, complete, disable |
| 120665–120667 | Systems | FDE key, decrypt, command run |
| 120670 | Software | Software inventory events |
| 120675 | MDM | MDM management events |
| 120680–120681 | Alerts | JumpCloud platform alerts |

---

## Grafana Dashboard Panels

The `jumpcloud_security.json` dashboard includes:

- **Auth Failures Over Time** — time series of failed logins
- **Auth Success Over Time** — time series of successful logins
- **Stat counters** — failures, successes, user lifecycle, brute-force, policy changes, MFA events
- **Events by Service** — pie chart (directory, sso, radius, ldap, etc.)
- **Events by Type** — horizontal bar chart of event types
- **SSO Application Usage** — bar chart of SSO app names
- **Auth Failures by Source IP** — table of top offending IPs
- **User Lifecycle Timeline** — stacked bar chart of user creates/deletes/updates
- **Recent Events** — raw event log table (last 50)

---

## Troubleshooting

### Bridge is running but no events in Wazuh

1. Check the bridge output file exists and has content:
   ```bash
   tail -5 /var/log/jumpcloud_events.jsonl
   ```
2. Verify Wazuh is tailing the file:
   ```bash
   grep jumpcloud /var/ossec/logs/ossec.log
   ```
3. Confirm the decoder fires:
   ```bash
   /var/ossec/bin/wazuh-logtest < /var/log/jumpcloud_events.jsonl
   ```

### API returns 401

- Verify `JUMPCLOUD_API_KEY` is set and valid.
- If using Doppler, confirm `doppler secrets get JUMPCLOUD_API_KEY` returns the key.

### No events returned from API

- JumpCloud Directory Insights retains 90 days of data.
- Check the service filter — `JUMPCLOUD_SERVICES=all` is the safest default.
- Increase `JUMPCLOUD_LOOKBACK_MINUTES` for the first run.

### Duplicate events

The bridge persists a cursor in `JUMPCLOUD_STATE`. If the state file is
deleted, events since the last `JUMPCLOUD_LOOKBACK_MINUTES` window may repeat.
This is harmless — Wazuh will index duplicates but rule frequency counts
reset each analysis cycle.
