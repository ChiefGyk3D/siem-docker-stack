# Target liveness alerts

`docker/prometheus/rules/target-up.yml` alerts when a `file_sd` scrape job
stops answering (`up == 0` for 5 minutes). It follows the `phone` label
taxonomy in [update-alerting.md](update-alerting.md): `phone=true` is the only
way an alert reaches the phone.

| Jobs | Alert | Severity | `phone` |
|------|-------|----------|---------|
| `twingate-ztna`, `unifi-controller`, `node` (the SIEM host's own exporter) | `CriticalTargetDown` | critical | `true` |
| `Computers`, `Cryptocurrency`, `AI`, `Security` | `TargetGroupDown` | warning | none |

Laptops and workstations sleep, so the warning groups never carry a `phone`
label. They still reach the normal alert channels.

## Absent targets

`up == 0` needs an `up` series. If a target file is missing, empty or
unreadable, the job has no series and nothing fires. For each critical job an
`absent(up{job="..."})` rule (`TwingateTargetsAbsent`, `UnifiTargetsAbsent`,
`SiemHostNodeTargetsAbsent`) fires after 10 minutes with `phone=true`. A fresh
install without `targets/node.json` (and the other two) will page until the
files exist; create them as described in
[docker/prometheus/targets/README.md](../docker/prometheus/targets/README.md).
The warning groups have no absent rule on purpose: they are optional.

The core stack jobs (prometheus, alertmanager, elasticsearch-exporter,
grafana, cadvisor) stay with `TargetDown` in `siem-health.yml`; the GPU jobs
are not covered here.

## Tests

`tests/python/test_target_up_alerts.py` checks that the file parses, labels
follow the taxonomy, `phone=true` appears only on the critical jobs, every
covered job is a `file_sd` job in `prometheus.yml`, and each critical job has
an absent rule.
