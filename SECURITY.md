# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
privately rather than opening a public issue.

- Preferred: open a [GitHub Security Advisory](https://github.com/ChiefGyk3D/siem-docker-stack/security/advisories/new)
  for this repository.
- Alternative: contact the maintainer directly through their GitHub profile
  ([@ChiefGyk3D](https://github.com/ChiefGyk3D)).

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce it, including any relevant component versions
  (OpenSearch, Logstash, Grafana, CrowdSec, etc.) involved.
- Any suggested mitigation, if known.

## Scope

This repository provides Docker Compose orchestration and configuration for
a SIEM stack. Vulnerabilities in the upstream container images themselves
(OpenSearch, Logstash, Grafana, CrowdSec, etc.) should be reported to those
projects directly.

## Response

This is a community-maintained project without a formal SLA. Reports are
reviewed as soon as reasonably possible, and a fix or mitigation is shipped
once the issue is confirmed.
