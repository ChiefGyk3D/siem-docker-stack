# Weekly update digest

An n8n workflow (`n8n/weekly-update-digest.json`) that posts one message every Monday at 07:00
America/New_York saying what was updated in the last week and what is still pending. Issue #202.

This is the workflow shell. The four source collectors are stubs that report `not-deployed` until
the real collectors land (UniFi #200, pfSense #70, OS packages and Twingate later). Until then the
digest says so in its "Not checked" section instead of pretending nothing happened.

## What it does

```
Weekly Schedule -> Window -> UniFi / OS Packages / Twingate / pfSense Collector
  -> Build Digest -> Discord Digest -> Matrix Digest -> Record Window
```

- Delivery is Discord and Matrix only. There is no phone path: no Pushover node, no Pushover
  credential, and no webhook trigger. The only trigger is the Schedule Trigger. A test enforces all
  of this on the workflow JSON.
- It always sends, including a quiet week ("0 applied, 0 still pending, 0 sources not checked").
  No branch can skip the send, so a missing digest means the workflow itself is broken.
- Each source reports exactly one of `ok`, `failed`, `not-deployed`. A source that failed or is not
  deployed is listed under "Not checked" and is never shown as "0 updates". Anything a collector
  returns that is not one of those three (an error item, a typo, no result) counts as `failed`.
- Message: title with the window in Eastern, a decision sentence ("N applied, M still pending, K
  sources not checked"), sections Applied, Still pending and Not checked, and a footer.
- Limits: long lists are cut with "+N more" to stay under the Discord limits (description 4096,
  6000 for the whole embed). The Not checked section and footer are never the part that is cut.
- Sanitizing: every device, package, version and reason string is coerced to a string, stripped of
  control characters, capped in length and markdown-escaped, and every `@` is broken so nothing can
  mention anyone. The built payload also carries `allowed_mentions` with an empty `parse` list; the
  n8n Discord node does not expose that field, so the escaping is what protects the Discord post.
  The Matrix message is a plain `m.notice` and pings nobody.

## Window

The window runs from the end of the last digest to now. The last end is kept in workflow static
data (`lastDigestEnd`), capped at 14 days back. With no usable last end the window is 7 days.
`Record Window` advances it only after delivery. If both Discord and Matrix fail, the run errors
(the workflow's error workflow fires) and the window is not advanced, so the next digest covers the
gap, up to the 14 day cap. If one channel fails the window advances and the run output says which.

Workflow static data persists only for an active workflow run by its schedule, not for manual test
executions.

## Setup

1. Import `n8n/weekly-update-digest.json` into n8n.
2. Discord: attach the existing `Discord Webhook Alerts` credential (Discord webhook type) to the
   `Discord Digest` node, the same credential the alert router uses.
3. Matrix credential: create an n8n Custom Auth credential named `matrix-bot-auth` and attach it to
   `Matrix Digest`. Its JSON sets the header `Authorization` to `Bearer <bot access token>`. The
   token lives only in the n8n credential store (fed from the secret manager); it is never in the
   workflow JSON or this repo.
4. Environment: set these on the n8n container, values from your own deployment (never committed):

   | Name | Meaning | Placeholder |
   | --- | --- | --- |
   | `MATRIX_HOMESERVER` | homeserver base URL, no trailing slash | `https://matrix.example.org` |
   | `MATRIX_ROOM_ID` | target room id | `!roomid:example.org` |

   n8n must allow `$env` in nodes (`N8N_BLOCK_ENV_ACCESS_IN_NODE` not set to `true`).
5. Set the error workflow in the workflow settings (the JSON carries the placeholder
   `ERROR_WORKFLOW_ID`), then activate the workflow. It is imported inactive.

The Matrix send is `PUT {homeserver}/_matrix/client/v3/rooms/{room}/send/m.room.message/{txnId}`
with `msgtype` `m.notice`. The transaction id is derived from the window end, so a retry of the
same run does not post twice.

## Writing a real collector

Replace the stub `Code` node body. Return one item:
`{ status, reason, applied: [{name, from, to}], pending: [{name, version}] }` with `status` one of
`ok`, `failed`, `not-deployed`. When the source cannot be read, return `failed` with a reason; never
return empty lists with `ok`. The node has `onError: continueRegularOutput`, so a crashed collector
is also treated as `failed`.

## Failure behavior

| Situation | Result |
| --- | --- |
| Source stub or not installed | listed under Not checked as "not deployed yet" |
| Source errors or returns junk | listed under Not checked as "check failed", counted in K |
| Quiet week | digest still sent, "0 applied" |
| Discord down | Matrix still sent, window advances |
| Matrix down | Discord still sent, window advances |
| Both down | run errors, window kept, next digest covers the gap (max 14 days) |
| Workflow not running | no digest: silence means broken |

Tests: `tests/python/test_update_digest.py` runs the Code node source under Node and carries
mutants for each guarantee above.
