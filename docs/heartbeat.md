# Alert path heartbeat

A dead-man's switch for the whole alert path. Every few minutes a synthetic
alert travels Grafana, the contact point and the n8n router, and the router
pings an observer that lives outside this host's failure domain. If the pings
stop, the observer alerts you through its own channels. Without it, a broken
alert path looks exactly like a quiet network.

Tracked in issue #80 (epic #62). Related: #77 (the update alert router) and
#78 (delivery failure reporting). See also
[docs/update-alerting.md](update-alerting.md).

## How it works

```
Grafana rule "Alert path heartbeat" (always firing, repeats every 5 min)
   |  labels: heartbeat=true, phone=false, severity=info
   v
contact point n8n-grafana-router  ->  n8n "Grafana SOAR - Alert Router"
                                          |
                          Normalize Alert -> Heartbeat?
                              no |              | yes
                       (normal alerts:           v
                        Discord, phone)   Build Heartbeat Ping -> Heartbeat Send?
                                                                   |
                                                         Heartbeat Ping (GET) -> Respond OK
                                                                   |
                                                                   v
                                                  observer (Healthchecks or Uptime Kuma)
                                                                   |
                                          no ping in period + grace -> its own alert channels
```

- **The rule** (`docker/grafana/provisioning/alerting/heartbeat-alert-rule.yml`)
  is titled "Alert path heartbeat". Its only query is the constant 1, so it
  needs no data source. Its state handling is `OK` for no data and for an
  evaluation error, on purpose: a rule that cannot evaluate must stop the pings,
  never look healthy.
- **The repeat** comes from the notification policy route in
  `heartbeat-notification-policy.yml.example`: `repeat_interval: 5m`,
  `group_interval: 1m`. Grafana can repeat only at a `group_interval` tick, so
  the real gap between pings is 5 to 6 minutes. Like the update-alert policy,
  the file is an example because Grafana loads one policy tree for the whole
  organization; merge the `heartbeat` route into your tree.
- **The router** takes a separate branch for `heartbeat=true`. It sends no
  Discord message and no phone message, ever, even if the label set is
  wrong. A body that is not a valid alert still goes to the malformed notice,
  so a heartbeat cannot hide a malformed call. The branch builds the ping in
  one Code node and sends it with one HTTP Request node, then answers 200 as for
  any alert.
- **Success** means the heartbeat reached the end of the branch: Grafana
  evaluated the rule and delivered the webhook, the header credential was
  accepted, and n8n normalized the body and ran the ping. A ping is therefore
  proof of the path from Grafana to the router and out to the observer. It is
  not proof that Discord or Pushover work (the heartbeat deliberately sends
  nothing to them); a failed Discord delivery is reported by the router as in
  [update-alerting.md](update-alerting.md#delivery-and-failure-reporting).

## Settings (environment of the n8n container)

| Variable | Meaning |
|----------|---------|
| `HEARTBEAT_PING_URL` | The observer's ping URL. Treat it as a secret: anyone holding it can fake a heartbeat. Off when unset or empty. Must start with `https://` or `http://`, at most 512 characters, no spaces. |
| `HEARTBEAT_KIND` | `healthchecks` (default) or `uptimekuma`. Any other value turns the feature off. |

The feature is off when unset: no ping, no error, and the router behaves as before.
Set the values in your secret manager or the n8n service's environment, never in
a file in this repository. Example for the n8n service in your compose file
(documentation-only values):

```yaml
  n8n:
    environment:
      - HEARTBEAT_PING_URL=${HEARTBEAT_PING_URL:-}
      - HEARTBEAT_KIND=${HEARTBEAT_KIND:-healthchecks}
      # n8n 2.x blocks env access in nodes unless this is false
      - N8N_BLOCK_ENV_ACCESS_IN_NODE=false
```

`N8N_BLOCK_ENV_ACCESS_IN_NODE=false` is needed on n8n versions that block
`$env` in nodes by default. While it is blocked, the heartbeat stays off and
the observer reports missed pings, which is the safe direction. The setting
also lets every node of every workflow on that n8n read the container
environment, so keep other secrets out of that container's environment (the
router's own secrets live in n8n credentials).

## The three observers

All three take a plain HTTP GET. Pick one; the settings are the same.

### 1. Hosted Healthchecks.io

`HEARTBEAT_KIND=healthchecks` (the default). The URL is the check's ping URL:

```
HEARTBEAT_PING_URL=https://hc-ping.com/<ping-uuid>
```

The router sends `GET <url>` for a good heartbeat and `GET <url>/fail` when the
heartbeat broke its contract (see Failure behavior). A trailing slash and any
query string on the configured URL are dropped before the suffix is added.

Set it up:

1. Create a check named "Alert path heartbeat" with a simple schedule, a period
   of 5 minutes and a grace time of at least 15 minutes. The real gap between
   pings is 5 to 6 minutes, so this tolerates a couple of lost pings before an alert.
2. Under Integrations, add the channels that must reach you when the check goes
   down (email, a chat service, a phone push). Choose channels that do not run
   through this stack.
3. Copy the check's ping URL into `HEARTBEAT_PING_URL` on the n8n container and
   restart n8n.
4. Enable the Grafana rule and the policy route (below). The check turns up after the
   first heartbeat; stop n8n for 15 minutes to see it go down.

### 2. Self-hosted Healthchecks or Uptime Kuma on another host

Same variables, with your own address. Run the observer on a different host, ideally
a different site or network, so a power or network failure of this host does not
take the observer with it.

```
# self-hosted Healthchecks
HEARTBEAT_KIND=healthchecks
HEARTBEAT_PING_URL=https://healthchecks.example.com/ping/<ping-uuid>

# self-hosted Uptime Kuma (a Push monitor)
HEARTBEAT_KIND=uptimekuma
HEARTBEAT_PING_URL=https://kuma.example.com/api/push/<push-token>

# a plain-HTTP observer on a documentation address (use TLS where you can)
HEARTBEAT_PING_URL=http://192.0.2.10:8000/ping/<ping-uuid>
```

For Uptime Kuma create a Push monitor with a heartbeat interval of 300 seconds
and retries so that about 10 minutes of silence marks it down, and attach
notification channels to it. The router replaces any query string on the push
URL with `?status=up&msg=OK` for a good heartbeat and
`?status=down&msg=heartbeat%20contract%20failed` for a broken one.

### 3. Cloud-hosted Uptime Kuma behind a private-access layer

Run Uptime Kuma on a cloud host that is reachable only through a private-access
(ZTNA) layer, so the push endpoint is not on the open internet. The n8n host
must be enrolled in that layer or reach the monitor through its private route,
and then it is the same as the second observer:

```
HEARTBEAT_KIND=uptimekuma
HEARTBEAT_PING_URL=https://kuma.internal.example.com/api/push/<push-token>
```

If the private-access layer itself goes down, the pings fail and the observer
reports missed pings: that is a real break in the path to the observer, so it
is the right signal. Keep the observer's alert channels (email, push) outside
the private layer so they still reach you.

## Failure behavior

- **Feature off when unset.** No URL, an empty or invalid URL, an unknown
  `HEARTBEAT_KIND`, or env access blocked by n8n: no ping is sent, nothing
  errors, and the router answers 200 for the heartbeat as for any alert. The
  observer then reports missed pings (if it exists).
- **A failed ping never fails the delivery of a real alert.** The HTTP Request
  node continues on error, so a timeout or an observer outage ends in a normal
  200 answer. Normal alerts do not use this branch at all.
- **A failed ping is retried up to 3 times, then dropped.** The node has Retry
  On Fail on, 3 tries, 2 seconds between tries and a 5 second request timeout,
  because one dropped ping (for example an intermittent certificate error on
  n8n's outbound call) used to be lost silently. The worst case is
  3 x 5 s + 2 x 2 s = 19 seconds before the node gives up and the branch answers
  200. If all tries fail, the ping is dropped and the next heartbeat is the
  retry. Certificate checking stays on: `allowUnauthorizedCerts` is not
  acceptable, because the ping URL is a secret and must only go to the real
  observer. Whether 19 seconds fits inside Grafana's webhook wait is unverified
  (the Grafana timeout was not checked); heartbeat delivery is not time critical.
- **Contract failure sends `/fail`.** A firing heartbeat whose `phone` label is
  not exactly `false` sends `/fail` (Healthchecks) or `status=down` (Uptime Kuma)
  immediately. Still no Discord or phone message is sent.
- **Resolved heartbeat sends nothing.** A resolved heartbeat (rule paused,
  deleted or no longer evaluating) means pings stop, and the observer's own
  timeout raises the alert.
- **No secret is logged or stored.** The Code node never logs and never copies
  alert content into the request; the request is a bare GET. The router stores
  neither successful nor failed executions ([update-alerting.md](update-alerting.md)),
  so the URL is not kept in execution data.
- **What stops the pings (and so alerts at the observer):** Grafana down or the
  rule broken, the contact point or its header credential wrong, n8n down or
  the workflow inactive, the route to the observer broken, or the setting unset.

## If the observer shows down when the path is up

Work through these in order. All of it is unverified against a live system.

1. Read the check's settings: use a simple schedule with a period of 5 minutes
   and a grace time of at least 15 minutes. A cron schedule or a short grace
   turns a 6 minute gap into a false alarm.
2. Read the check's ping log. Gaps with no entry mean pings never arrived (look
   at n8n and the network); a `/fail` entry means the router saw a heartbeat
   that broke its contract (the `phone` label), which is a different problem.
3. Compare the gap times with the n8n container logs for TLS or connection
   errors on the outbound call. Retries now cover a one-off drop; a gap longer
   than the three tries points at something steadier.
4. If the errors are certificate trust errors (something inspecting outbound
   TLS), fix the trust, not the check: add the inspecting CA to the n8n
   container with `NODE_EXTRA_CA_CERTS` (a path to a CA bundle file mounted into
   the container), or exempt the observer host from inspection. Do not set
   `allowUnauthorizedCerts`. Both options are unverified here; check n8n's and
   your inspecting device's current docs.

## Enable it

1. Deploy `heartbeat-alert-rule.yml` into Grafana's provisioning alerting folder
   (next to the other rule files). `scripts/live-deploy/grafana-deploy.py`
   copies it with the other alerting files ([live-deploy-runbook.md](live-deploy-runbook.md),
   step 5); stage it with the others. Grafana loads a new rule file only at
   startup, so restart Grafana (the script's `--apply` recreates the container).
2. Merge the `heartbeat` route from `heartbeat-notification-policy.yml.example`
   into your notification policy tree (Alerting, Notification policies). This
   stays a manual or API merge, not part of the deploy: Grafana loads one
   policy tree per organization, so a provisioned file would replace the tree.
3. Import the updated `n8n/grafana-alert-router.json` and activate it.
4. Set `HEARTBEAT_PING_URL` (and `HEARTBEAT_KIND`) on the n8n container and
   restart it. `.env.example` lists the names.
5. Confirm the observer shows pings roughly every 5 to 6 minutes, then test
   the failure path: stop n8n and wait for the observer's alert.

## Verified and unverified

Verified (the repository tests, `tests/python/test_heartbeat.py`, which run
the Code node and the expressions under Node and walk the router graph with a
model of n8n):

- a heartbeat sends no Discord, Pushover or malformed notice and exactly one
  ping; a ping follows only after the branch ran and before the answer;
- a failed ping, an off or invalid setting and a blocked env all answer 200;
- the URL forms for both kinds and the `/fail` and `status=down` paths;
- normal alerts keep their routing, 502 handling and phone label gate;
- no ping URL or key is stored in any file of the repository.

Verified (n8n docs, https://docs.n8n.io/workflows/components/nodes/, read
2026-11-20): Retry On Fail reruns a failed node until it succeeds, and the
"Continue" error setting proceeds to the next node despite the error. The HTTP
Request timeout is milliseconds to the initial response
(https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.httprequest/,
read 2026-11-20).

Unverified (not checked against a live system or the vendors' current docs in
this change):

- n8n: that after all retries fail, Continue (regular output) goes on to Respond
  OK and the answer stays 200 (the docs read did not state the order; the
  repository model assumes it), the Max Tries and Wait Between Tries limits, and
  that a timeout counts as a failed try;

- n8n: `$env` access in Code nodes with `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`,
  and the HTTP Request node's continue-on-error (`continueRegularOutput`) for a
  ping failure behaving like the modeled one;
- Grafana: that a rule made only of expressions (a math constant and a
  threshold) provisions and fires on your version, and the real gap between
  repeats (5 to 6 minutes) against `repeat_interval`;
- Healthchecks.io and Uptime Kuma: the `/fail` suffix, the push `status` query,
  and the period and grace fields, as described above from memory of their docs.
  Check each against the observer's current documentation before relying on it.

## Tests

```
python3 -m pytest tests/python/test_heartbeat.py -q
```

Node is required, as for the other router tests.

## Related

A second P1 channel that does not depend on n8n: [channel-redundancy.md](channel-redundancy.md).
