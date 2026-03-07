# Maintenance Guide

## Automated Maintenance

### Docker Health Checks

All services have built-in Docker health checks. Monitor them with:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Recommended Systemd Timers

Set up automated maintenance on your SIEM server:

```bash
# Create a weekly Docker image update timer
sudo tee /etc/systemd/system/siem-docker-update.timer <<EOF
[Unit]
Description=Weekly SIEM Docker image updates

[Timer]
OnCalendar=Sun 03:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo tee /etc/systemd/system/siem-docker-update.service <<EOF
[Unit]
Description=Update SIEM Docker images

[Service]
Type=oneshot
WorkingDirectory=/opt/siem
ExecStart=/bin/bash -c 'docker compose pull && docker compose up -d'
User=root
EOF

sudo systemctl daemon-reload
sudo systemctl enable siem-docker-update.timer
sudo systemctl start siem-docker-update.timer
```

### Daily Health Check Timer

```bash
sudo tee /etc/systemd/system/siem-health-check.timer <<EOF
[Unit]
Description=Daily SIEM health check

[Timer]
OnCalendar=*-*-* 06:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo tee /etc/systemd/system/siem-health-check.service <<EOF
[Unit]
Description=SIEM Stack health check

[Service]
Type=oneshot
ExecStart=/opt/siem-docker-stack/scripts/05-verify.sh localhost
User=root
EOF

sudo systemctl daemon-reload
sudo systemctl enable siem-health-check.timer
sudo systemctl start siem-health-check.timer
```

## Manual Maintenance Tasks

### Checking Service Logs

```bash
# All services
cd /opt/siem && docker compose logs --tail=50

# Specific service
docker compose logs --tail=100 -f opensearch-hot
docker compose logs --tail=100 -f logstash
docker compose logs --tail=100 -f wazuh-manager
```

### Restarting Services

```bash
# Restart a single service
docker compose restart grafana

# Restart the entire stack (graceful)
docker compose down && docker compose up -d

# Force recreate (picks up config changes)
docker compose up -d --force-recreate
```

### OpenSearch Maintenance

```bash
# Check cluster health
curl -s 'http://localhost:9200/_cluster/health?pretty'

# Check node allocation tiers
curl -s 'http://localhost:9200/_cat/nodeattrs?v&h=node,attr,value' | grep temp

# List all indices sorted by size
curl -s 'http://localhost:9200/_cat/indices?v&s=store.size:desc'

# Check ISM policy execution
curl -s 'http://localhost:9200/_plugins/_ism/explain/*' | jq '.'

# Force ISM retry on a stuck index
curl -X POST 'http://localhost:9200/_plugins/_ism/retry/suricata-2024.01.15'

# Check shard allocation
curl -s 'http://localhost:9200/_cat/shards?v&s=store:desc' | head -20
```

### InfluxDB Maintenance

```bash
# List databases
curl -s 'http://localhost:8086/query?q=SHOW+DATABASES' | jq .

# Check series cardinality
docker exec influxdb influx -execute 'SHOW SERIES CARDINALITY ON pfsense'

# Drop old data (careful!)
docker exec influxdb influx -execute 'DELETE FROM /.*/ WHERE time < now() - 365d' -database pfsense
```

### Grafana Maintenance

```bash
# Reset admin password
docker exec grafana grafana cli admin reset-admin-password newpassword

# Check provisioned datasources
curl -s -u admin:changeme 'http://localhost:3000/api/datasources' | jq '.[].name'

# Export a dashboard
curl -s -u admin:changeme 'http://localhost:3000/api/dashboards/uid/YOUR_UID' | jq '.dashboard' > exported.json
```

### Wazuh Maintenance

```bash
# Check Wazuh manager status
docker exec wazuh-manager /var/ossec/bin/agent_control -l

# Check connected agents
docker exec wazuh-manager /var/ossec/bin/agent_control -l | grep -c Active

# Restart Wazuh manager
docker compose restart wazuh-manager

# Check Wazuh indexer health
curl -sk -u admin:SecretPassword 'https://localhost:9202/_cluster/health?pretty'
```

## Backup Strategy

### Critical Data to Back Up

| Data | Location | Frequency |
|------|----------|-----------|
| Grafana database | `/data/warm/grafana/` | Weekly |
| Wazuh configuration | `/data/hot/wazuh/manager/etc/` | After changes |
| Docker configs | `/opt/siem/` | After changes |
| OpenSearch ISM policy | Export via API | After changes |
| .env file | `/opt/siem/.env` | After changes |

### Quick Backup Script

```bash
#!/bin/bash
BACKUP_DIR="/data/warm/backups/$(date +%Y-%m-%d)"
mkdir -p "$BACKUP_DIR"

# Grafana
tar czf "$BACKUP_DIR/grafana.tar.gz" -C /data/warm grafana/

# Wazuh config
tar czf "$BACKUP_DIR/wazuh-config.tar.gz" -C /data/hot/wazuh/manager etc/

# Docker configs
tar czf "$BACKUP_DIR/siem-configs.tar.gz" -C /opt siem/

# ISM policy
curl -sf 'http://localhost:9200/_plugins/_ism/policies' > "$BACKUP_DIR/ism-policies.json"

echo "Backup saved to $BACKUP_DIR"
```

## Updating the Stack

```bash
cd /opt/siem

# Pull latest images
docker compose pull

# Recreate containers with new images
docker compose up -d

# Verify everything is healthy
bash /path/to/scripts/05-verify.sh localhost
```

## Disk Space Emergency

If a disk fills up:

1. **Check what's using space:**
   ```bash
   du -sh /data/hot/* /data/warm/*
   ```

2. **Delete old OpenSearch indices manually:**
   ```bash
   # List oldest indices
   curl -s 'http://localhost:9200/_cat/indices?v&s=creation.date'

   # Delete a specific old index
   curl -X DELETE 'http://localhost:9200/suricata-2024.01.01'
   ```

3. **Prune Docker:**
   ```bash
   docker system prune -f
   docker volume prune -f  # Only if you know what you're doing!
   ```

4. **Clean Docker logs:**
   ```bash
   truncate -s 0 /var/lib/docker/containers/*/*-json.log
   ```
