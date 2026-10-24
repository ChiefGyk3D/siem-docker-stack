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

- 17 Grafana holds InfluxDB and Wazuh indexer admin credentials
- 27 Default Wazuh credentials used when `.env` is incomplete
- 28 Hard-coded kibanaserver/kibanaserver for the Wazuh dashboard
- 29 Known fallback passwords across the stack (`${VAR:-changeme}` in compose)
- 32 Portainer with read-write Docker socket starts by default on a public port

No Critical threats are recorded. 41 threats in total: 35 Open, 6 Mitigated.

## UNVERIFIED items

- Whether Wazuh agent enrollment (1515) requires a password (set outside the repo).
- How n8n is exposed and whether a proxy adds webhook authentication.
- Logstash `type` handling for attacker-supplied JSON on UDP 5140 (not run).
- Possible regex backtracking in the grok/dissect patterns (not tested).
- Stored XSS or panel injection from log fields in Grafana/Dashboards (not tested).
- Whether the stock Wazuh indexer user database keeps the default kibanaserver hash.
- Portainer first-run admin lockdown behavior in the `lts` image.

## Not covered

Runtime state of any deployment, the content of `.gitleaksignore`, the
upstream images' own vulnerabilities, and the Wazuh rule logic.
