# Threat model

`siem-docker-stack.threat-dragon.json` is an OWASP Threat Dragon v2 model of
the compose stack as built: OpenSearch hot/warm, Logstash, syslog-ng, Grafana,
InfluxDB, Prometheus, Alertmanager, Wazuh (manager, indexer, dashboard),
optional CrowdSec, UniFi Poller and Portainer, plus the n8n/Discord alert path
and the CI/image supply chain. Every cell and threat cites the file it came
from. The stack has no LLM or AI component (`n8n/ideas.md` only mentions
local LLMs as ideas), so there are no prompt-injection threats.

Open it with OWASP Threat Dragon (desktop or web app): File > Open, choose the
JSON file. Source of truth is `docker/docker-compose.yml`, `docker/*/` configs,
`scripts/`, `n8n/` and `wazuh/` at the commit the model was written against.

## Trust boundaries

- Untrusted network: anything that can reach published ports. Docker-published
  ports bypass UFW, so the host firewall is not a boundary.
- SIEM host / `siem-net`: one flat bridge, no segmentation between services.
- Host OS and Docker daemon: bind mounts, `.env`, key material, Docker socket.
- External services: n8n (not in compose), Discord, VirusTotal, UniFi controller.
- Supply chain and CI: container registries, plugin catalog, GitHub Actions.

## Open High or Critical threats

- 17 Grafana holds the Wazuh indexer admin credential (the InfluxDB half is
  fixed: Grafana now reads InfluxDB with a read-only account). Open because
  the repo has no read-only role for the Wazuh indexer.

No Critical threats are recorded. 41 threats in total: 30 Open, 11 Mitigated.

## Mitigated by issue #32

- 27 Default Wazuh credentials: `WAZUH_*_PASSWORD` are required variables
  (`${VAR:?}`) in `docker/docker-compose.yml`; `scripts/check-env.sh` rejects
  known defaults.
- 28 Hard-coded kibanaserver: `docker/wazuh/opensearch_dashboards.yml` reads
  `${DASHBOARD_PASSWORD}` from `WAZUH_DASHBOARD_PASSWORD`.
- 29 Fallback passwords: no secret has a `:-` default in compose or in the
  Logstash pipelines; `tests/python/test_compose_security.py` enforces it.
- 32 Portainer: behind the `portainer` compose profile, loopback bind.
- 14 Warm node port: binds to `BIND_ADDR` (loopback by default).

Also reduced but still Open: 11, 20, 21 (exposure now opt-in), 30 (secrets
now only in `.env`; Grafana CLI reset still uses a command-line password),
34 (UniFi poller uses a write-only InfluxDB account; TLS verify still off).

## UNVERIFIED items

- Whether Wazuh agent enrollment (1515) requires a password (set outside the repo).
- How n8n is exposed and whether a proxy adds webhook authentication.
- Logstash `type` handling for attacker-supplied JSON on UDP 5140 (not run).
- Possible regex backtracking in the grok/dissect patterns (not tested).
- Stored XSS or panel injection from log fields in Grafana/Dashboards (not tested).
- Whether `change-passwords.sh` rotates the kibanaserver hash correctly on a live Wazuh 4.9 indexer (written, not run: no containers were started).
- Whether Logstash 8.9 and the Wazuh dashboard expand `${VAR}` exactly as the changes assume (CI runs `logstash --config.test_and_exit` with a throwaway value set, so it proves the syntax, not the unset failure).
- Portainer first-run admin lockdown behavior in the `lts` image.

## Not covered

Runtime state of any deployment, the content of `.gitleaksignore`, the
upstream images' own vulnerabilities, and the Wazuh rule logic.
