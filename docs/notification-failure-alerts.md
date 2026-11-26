# Notification failure alerts

Issue #81 (epic #62). A Grafana alert rule that fires when Grafana itself
failed to deliver a notification through a contact point.

## What it catches and what it cannot

Catches: Grafana tried to send and the attempt failed. Examples: n8n is down or
refuses the connection, the secret header is rejected, the router returns a 5xx,
Discord rejects the webhook.

Cannot catch: a router that answers 200 and then drops the alert, or a Discord
step that fails inside n8n after the router said received. Those are the delivery
failure reporting in #78 and the alert path heartbeat in #80 (`docs/heartbeat.md`).

## How it works

- Grafana's own `/metrics` is scraped by the `grafana` job in
  `docker/prometheus/prometheus.yml`. No scrape change was needed.
- The rule `docker/grafana/provisioning/alerting/notification-failure-alert-rule.yml`
  runs `sum by (integration) (increase(grafana_alerting_notifications_failed_total[10m]))`
  on the Prometheus data source and fires when it stays above 0 for 5 minutes.
  The 10 minute window is written once, in the query. Change `for` to change the
  hold time.
- Labels: `severity=warning`, `alert_group=alert-path`, `delivery_failure=true`.
  There is no `update_alert`, `heartbeat` or `phone` label.
- States: `noDataState: OK` (the counter does not exist until a first failure)
  and `execErrState: Alerting` (a failing query must not hide failures).

## Deploying the rule

`scripts/live-deploy/grafana-deploy.py` deploys `notification-failure-alert-rule.yml`
with the other alerting files: stage it, run the script without flags for a dry
run, then with `--apply` ([live-deploy-runbook.md](live-deploy-runbook.md), step 5).
The `.example` contact point and policy files here are not part of that deploy.

## Routing: a different path on purpose

An alert about failed webhook deliveries must not use that webhook. The shipped
examples route `delivery_failure=true` to a direct Discord contact point:

- `notification-failure-contact-point.yml.example` defines `discord-direct`,
  reading the webhook URL from `$DISCORD_FAILURE_WEBHOOK_URL` in the Grafana
  container environment. Use a different webhook from n8n's if you can.
- `notification-failure-notification-policy.yml.example` is the policy route.
  Merge it into your tree (the policy is one tree per organization).

To route it elsewhere (email, another webhook), change only the `receiver` on that
policy route. The rule does not change.

## Unverified: the metric name

`grafana_alerting_notifications_failed_total{integration,org}` is the name
Grafana's documentation lists, and it is UNVERIFIED here. On a live Grafana 12.4
(2026-11-19) `grafana_alerting_notifications_total` and
`grafana_alerting_notification_requests_total` exist, but the failed counter was
absent because Grafana creates a labeled counter only after its first event.
Also unverified: that `increase()` reports the first failure (it needs two
samples), and that the rule provisions cleanly on your Grafana version.

To confirm on a live instance, force one failed delivery safely:

1. Create a temporary contact point of type webhook pointing at
   `http://localhost:9/` (nothing listens there) and use its Test button in
   Grafana. Do not change the real policy tree.
2. Read the counter (from a host that can reach Grafana's metrics):
   `curl -s http://grafana:3000/metrics | grep notifications_failed`
3. If the name differs, change the one metric name in query A of the rule file.
4. Delete the temporary contact point.

Whether the Test button increments the counter is itself unverified; if it does
not, point a temporary policy route at the broken contact point and fire a test
alert.

## Tests

```
python3 -m pytest tests/python/test_notification_failure_alert.py -q
```
