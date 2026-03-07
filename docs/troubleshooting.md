# Troubleshooting Guide

## Common Issues

### OpenSearch won't start

**Symptom:** `opensearch-hot` or `opensearch-warm` exits immediately or restarts in a loop.

**Cause 1: `vm.max_map_count` too low**
```bash
# Check current value
sysctl vm.max_map_count

# Fix (temporary)
sudo sysctl -w vm.max_map_count=262144

# Fix (permanent — done by 02-bootstrap.sh)
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-siem.conf
sudo sysctl --system
```

**Cause 2: Permission denied on data directory**
```bash
# OpenSearch runs as UID 1000 inside the container
sudo chown -R 1000:1000 /data/hot/opensearch /data/warm/opensearch
```

**Cause 3: Disk full**
```bash
df -h /data/hot /data/warm
# Delete old indices if needed
curl -X DELETE 'http://localhost:9200/suricata-2024.01.01'
```

---

### OpenSearch cluster health is RED

**Symptom:** `curl localhost:9200/_cluster/health` shows `"status": "red"`.

```bash
# Check unassigned shards
curl -s 'http://localhost:9200/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason' | grep UNASSIGNED

# Most common: retry allocation
curl -X POST 'http://localhost:9200/_cluster/reroute?retry_failed=true'

# If warm node is down, indices trying to move to warm will be unassigned
docker compose restart opensearch-warm
```

---

### Logstash not receiving logs

**Symptom:** No new indices appearing in OpenSearch.

```bash
# Check Logstash logs
docker compose logs --tail=50 logstash

# Verify Logstash is listening
docker exec logstash ss -tulnp | grep -E '5140|5044|5045'

# Test UDP input (Suricata)
echo '{"timestamp": "2024-01-01T00:00:00.000Z", "event_type": "alert"}' | nc -u localhost 5140

# Check if OpenSearch is reachable from Logstash
docker exec logstash curl -sf http://opensearch-hot:9200/_cluster/health
```

---

### Grafana shows "No Data"

**Symptom:** Dashboard panels show "No data" or errors.

1. **Check datasource connectivity:**
   - Go to Grafana → Connections → Data Sources → Click each one → "Save & Test"

2. **Check if indices exist:**
   ```bash
   curl -s 'http://localhost:9200/_cat/indices?v' | grep -E 'suricata|syslog|pfblockerng'
   ```

3. **Check time range:**
   - Grafana defaults to "Last 6 hours" — expand to "Last 7 days" if indices are older

4. **Provisioning issue:**
   ```bash
   # Check Grafana logs for provisioning errors
   docker compose logs grafana | grep -i error
   
   # Force re-read of provisioned dashboards
   docker compose restart grafana
   ```

---

### Syslog-ng not receiving logs

**Symptom:** No syslog data flowing to OpenSearch.

```bash
# Check syslog-ng is listening
docker exec syslog-ng ss -tulnp | grep 514

# Check syslog-ng internal stats
docker exec syslog-ng syslog-ng-ctl stats | head -20

# Verify pfSense is sending:
# On pfSense: Status → System Logs → Settings → Remote Logging
# Should point to your SIEM_HOST:514 (UDP)

# Test manually
echo "<14>Test syslog message" | nc -u localhost 514

# Check local archives are being written
ls -la /data/warm/archives/syslog/
```

---

### Wazuh Dashboard not loading

**Symptom:** HTTPS on port 443 returns an error or doesn't load.

```bash
# Check all Wazuh containers are running
docker ps | grep wazuh

# Check certificates exist
ls -la docker/wazuh/certs/

# If certs are missing:
bash scripts/06-generate-wazuh-certs.sh

# Check Wazuh Dashboard logs
docker compose logs --tail=50 wazuh-dashboard

# Check Wazuh Indexer health
curl -sk -u admin:SecretPassword https://localhost:9202/_cluster/health
```

---

### Wazuh agents can't connect

**Symptom:** Agents show as "Disconnected" in Wazuh manager.

```bash
# Check manager is listening
docker exec wazuh-manager ss -tulnp | grep -E '1514|1515'

# Check firewall
sudo ufw status | grep -E '1514|1515'

# Check agent enrollment
docker exec wazuh-manager /var/ossec/bin/agent_control -l

# Verify manager log
docker exec wazuh-manager tail -50 /var/ossec/logs/ossec.log
```

---

### Container keeps restarting

**Symptom:** A container is in a restart loop.

```bash
# Check which container(s)
docker ps -a --format "table {{.Names}}\t{{.Status}}" | grep -i restart

# Check exit code
docker inspect --format='{{.State.ExitCode}}' <container_name>

# Check the last logs before crash
docker logs --tail=100 <container_name>

# Common causes:
# Exit code 137 = OOM killed (increase container memory or reduce heap)
# Exit code 1   = Configuration error (check logs)
# Exit code 78  = Elasticsearch/OpenSearch config error
```

---

### High memory usage

**Symptom:** Server running out of RAM, OOM kills.

```bash
# Check total JVM heap allocation
# opensearch-hot:  12g (default)
# opensearch-warm:  4g (default)
# wazuh-indexer:    4g (default)
# logstash:         2g (default)
# Total JVM:       22g — needs at least 32GB RAM with OS overhead

# For 16GB RAM systems, reduce heaps:
# OPENSEARCH_HOT_HEAP=4g
# OPENSEARCH_WARM_HEAP=2g
# WAZUH_INDEXER_HEAP=2g
# LOGSTASH_HEAP=1g

# Check current usage
docker stats --no-stream
```

**Memory Budget Guidelines:**

| Total RAM | Hot Heap | Warm Heap | Wazuh Heap | Logstash | Free for OS |
|-----------|----------|-----------|------------|----------|-------------|
| 16 GB | 4g | 2g | 2g | 1g | ~7 GB |
| 32 GB | 8g | 4g | 4g | 2g | ~14 GB |
| 64 GB | 12g | 4g | 4g | 2g | ~42 GB |
| 128 GB | 24g | 8g | 8g | 4g | ~84 GB |

> **Rule of thumb:** JVM heaps should never exceed 50% of total RAM. Leave at least 30% for OS caches and other services.

---

### InfluxDB high cardinality

**Symptom:** InfluxDB uses excessive memory or queries are slow.

```bash
# Check series cardinality
docker exec influxdb influx -execute 'SHOW SERIES CARDINALITY ON pfsense'
docker exec influxdb influx -execute 'SHOW SERIES CARDINALITY ON unpoller'

# If cardinality is >1M, consider dropping old series
docker exec influxdb influx -execute 'DROP SERIES FROM /.*/ WHERE time < now() - 90d' -database unpoller
```

---

## Logs Reference

| Service | How to Check Logs |
|---------|-------------------|
| OpenSearch Hot | `docker compose logs opensearch-hot` |
| OpenSearch Warm | `docker compose logs opensearch-warm` |
| Logstash | `docker compose logs logstash` |
| Grafana | `docker compose logs grafana` |
| Syslog-ng | `docker compose logs syslog-ng` |
| Wazuh Manager | `docker compose logs wazuh-manager` |
| Wazuh Indexer | `docker compose logs wazuh-indexer` |
| Wazuh Dashboard | `docker compose logs wazuh-dashboard` |
| InfluxDB | `docker compose logs influxdb` |
| Prometheus | `docker compose logs prometheus` |

## Getting Help

1. Check the specific service documentation:
   - [OpenSearch](https://opensearch.org/docs/latest/)
   - [Wazuh](https://documentation.wazuh.com/current/)
   - [Grafana](https://grafana.com/docs/grafana/latest/)
   - [Logstash](https://www.elastic.co/guide/en/logstash/current/index.html)

2. Check GitHub Issues on this repo

3. For pfSense integration, see the companion repo: [pfsense_siem_stack](https://github.com/ChiefGyk3D/pfsense_siem_stack)
