# Owner runbook: bring the alerting platform fully online

One ordered list of every LIVE step the owner does to finish the alerting
platform (epic #62). Nothing in this repository does these steps for you. Each
step names the doc it comes from, what must be true first, the exact commands,
what to watch, and how to undo it.

Written 2026-11-19 against `origin/master` at commit `a503203`. Steps 0 to 6.3
were audited again on 2026-11-20 against `origin/master` at commit `a4cdb72`
(issue #174); `tests/python/test_owner_runbook.py` keeps the machine-checkable
parts true. Every fact is marked:

- VERIFIED: stated in a repo doc or file, and the doc is cited. VERIFIED means
  "a repo doc says so", not "seen on the live system". Most live behavior is
  still unconfirmed; the source docs say which parts (see their "unverified"
  sections).
- INFERRED: a reasonable reading that no cited doc states. Check it before
  relying on it.
- OPEN QUESTION: a doc is unclear or a name is unknown. Nothing is guessed;
  the owner decides or looks it up.

## Placeholders and conventions

| Placeholder | Meaning |
|-------------|---------|
| `LOGGING_BOX` | The SIEM host that runs the stack |
| `KEY_FILE` | Path to the SSH private key for LOGGING_BOX |
| `REPO_DIR` | Absolute path of a copy of this repository's `scripts`, `n8n`, `docs` and alerting files on LOGGING_BOX, made by step 0a (for example `/home/YOU/siem-docker-stack`). It is NOT `/opt/siem`: that is the deployed stack and has no `n8n` folder and no `live-deploy` scripts |
| `SIEM_DIR` | Live stack directory, default `/opt/siem` (`docs/live-deploy-runbook.md`, variable table) |
| `dev_network`, `DEV_CONFIG` | The Doppler branch config under the `dev` environment of project `homelab` that holds every new alerting value (created in step 0b). `DEV_CONFIG` is the placeholder name the live deploy runbook uses for the same config; its value is `dev_network` |
| `ROUTER_ID` | The n8n id (16 hex characters) of the LIVE router workflow "Grafana SOAR - Alert Router (authenticated)". The router import does NOT print it: read it with `docker exec n8n n8n list:workflow` or from the workflow's address in the n8n interface (the id is in the URL). Passing it makes the import overwrite that workflow; leaving it out makes a second copy with a new id |
| `HANDLER_ID` | The n8n id of the live error handler workflow "Alert Router Error Handler". Printed as `error workflow id:` by the handler import (`docs/live-deploy-runbook.md`, section 3); on a live box read it the same way as `ROUTER_ID` |
| `OLD_ROUTER_ID` | The n8n id of the old router that step 9 deactivates (Q5); read it the same way |
| `OLD_SLUG` | The slug of the `dev_network` service token being revoked in step 0b.5 (read it from `doppler configs tokens --project homelab --config dev_network`) |
| `SERVICE_ACCOUNT` | The dedicated non-login account of step 0c (suggested name `siem-ops`) |
| `N8N_COMPOSE_FILE`, `N8N_COMPOSE_DIR` | The compose file that runs n8n and its folder. The live values are `/opt/n8n/docker-compose.yml` and `/opt/n8n` (VERIFIED by the lead 2026-11-20). INFERRED root owned, because the step 6.2 run used `sudo` for every touch of it; so copies, edits and `docker compose` runs against it below use `sudo` too |
| `HOST_PORT`, `CONTAINER_PORT` | The loopback port you publish for n8n on the host and the port n8n listens on inside its container (section 6.0) |
| `SIEM_NETWORK` | The real name of the Docker network the stack's containers share, from `docker network ls` (usually the compose project name plus `_siem-net`) |
| `PRIVATE_WEBHOOK_PATH` | The Grafana router's private path, the content of the `router-path` file in the helper's config directory. An address, not a credential, but keep it out of git and chat |
| `EXPIRY_WATCH_PRIVATE_PATH` | The expiry watch's private path, the content of the `expiry-path` file in the same directory |
| `ARCHIVE_FILE` | The `.tar.gz.age` archive a backup run wrote (step 2d) |
| `OBSERVER_HOSTNAME` | The host name inside the heartbeat observer's ping URL (step 7) |
| `VARIABLE_NAME` | A variable name from the table in 6b |
| `PREVIOUS_RELEASE_DIR` | The `previous:` release folder that step 0a printed when it flipped the repo link, an absolute path under `/opt/siem-repo-releases` |
| `EXPECTED_SHA256` | The sha256 of the repo archive, printed on YOUR WORKSTATION by step 0a (never read from the box) |

Session variables. The three multi-line session blocks below (the SAFE N8N
RECREATE, the router chain and the router rollback) do not paste placeholders into
command positions. Instead, you set five shell variables ONCE in the session, and
the check function refuses to run anything if one of them has an unexpected shape,
so a value with a space or a shell metacharacter can never become syntax. Every
expansion in those blocks is quoted. Paste this at the start of the session, with
your real values (`REPO_DIR` and the compose folder are paths, the ids are 16 hex
characters, the network name is letters, digits, dot, dash and underscore). The
blocks need `bash` (they use functions, `local` and `[[ ]]`): start the session with
a clean one, `bash --noprofile --norc`. A function that is marked read-only in an
older shell cannot be replaced; the blocks detect that and print `STALE FUNCTION`,
and the answer is always a fresh shell:

```
OWNER_FRESH=1; for F in owner_chk_vars owner_recreate_n8n owner_router_chain owner_router_rollback owner_prune_releases owner_rehearse_down owner_rehearse_router; do unset -f "$F" 2> /dev/null; if declare -f "$F" > /dev/null 2>&1; then OWNER_FRESH=0; echo "STALE FUNCTION: $F cannot be removed (read-only or inherited): open a fresh bash shell"; fi; done
REPO_DIR=/opt/siem-repo
N8N_COMPOSE_DIR=/opt/n8n
SIEM_NETWORK=siem_siem-net
ROUTER_ID=0000000000000000
HANDLER_ID=0000000000000000
owner_chk_vars() {
  : "runbook-block-chk-vars-v3"
  local v re_path='^/[A-Za-z0-9._/-]+$' re_id='^[0-9a-f]{16}$' re_net='^[A-Za-z0-9._-]+$'
  for v in "$REPO_DIR" "$N8N_COMPOSE_DIR"; do [[ "$v" =~ $re_path ]] || { echo "bad path variable"; return 1; }; done
  for v in "$ROUTER_ID" "$HANDLER_ID"; do [[ "$v" =~ $re_id ]] || { echo "bad workflow id"; return 1; }; done
  [[ "$SIEM_NETWORK" =~ $re_net ]] || { echo "bad network name"; return 1; }
  return 0
}
OWNER_SUM_CHK="$(declare -f owner_chk_vars | sha256sum | cut -d' ' -f1)"
if [ "$OWNER_FRESH" = 1 ] && [ "$(declare -f owner_chk_vars | sha256sum | cut -d' ' -f1)" = "$OWNER_SUM_CHK" ]; then owner_chk_vars && echo "variables ok"; else echo "STALE FUNCTION: open a fresh bash shell and paste again"; false; fi
```

The values above are examples only: replace the two ids with the live ones (`n8n
list:workflow`) and the network with the one from `docker network ls`. `owner_chk_vars`
must print `variables ok`. It checks every variable on its own with anchored patterns
that cannot match across lines, so an empty value, a value with a newline, a carriage
return, a space or a metacharacter is refused.

Rules every step follows:

- SSH always names the key and refuses other identities:
  `ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX '...'`. Blocks marked
  "in a session" are pasted after opening one with
  `ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX`.
- `doppler secrets set` echoes the value by default, so every such command
  carries `--silent` and ends with `> /dev/null` (VERIFIED: `--silent` per
  Doppler's setting-secrets page, read 2026-11-19; `> /dev/null` per
  `docs/update-alerting.md`, webhook authentication, step 1). Secret values go
  in on stdin, never on a command line.
- New secrets go in project `homelab`, config `dev_network`, never `prd_network`
  or any prd config, until the owner says the stack is live in production.
- No secret value, host name, real domain or personal detail is written in this
  file. Addresses use `example.com`; the documentation range 192.0.2.x stands
  for real ones.
- Do one step at a time. Verify each before the next.

## Open questions (the repo cannot answer these)

| # | Question | Where it bites |
|---|----------|----------------|
| Q1 | RESOLVED (2026-11-20). `docs/live-deploy-runbook.md` points here for `DEV_CONFIG`: it is the Doppler config `dev_network` (step 0b). | Steps 4g, 5 |
| Q4 | The names `FAILTEST` (workflow and credential) appear in no repo doc. The closest text is the failure-path test copy in `docs/live-deploy-runbook.md`, section 4, items 1 to 6 ("the copy", "a wrong credential in the copy"). Read the exact names in the n8n UI and the ids with `docker exec n8n n8n list:workflow` (INFERRED command; check `n8n list:workflow --help`). | Step 3 |
| Q5 | What is the live name of the old router workflow? The repo workflow is named "Grafana SOAR - Alert Router" and the runbook calls the new one "Grafana SOAR - Alert Router (authenticated)". Which one is live and old is not in a doc; tell them apart by id (`ROUTER_ID` versus `OLD_ROUTER_ID`), not by name. | Step 9 |
| Q7 | RESOLVED by the deploy script change (PR #126, issue #125, merged: commit `862b687`). `scripts/live-deploy/grafana-deploy.py` deploys the notification failure rule and, only when you name them with `--include-example`, the P1 email contact point and policy examples. It does NOT deploy `notification-failure-contact-point.yml.example` (`discord-direct`): that one is always copied by hand (4c). It defaults to a dry run, needs `--apply`, and backs up every file it replaces. It never starts docker and never reads the compose file, so the compose line and the restart stay manual (step 4b and 4d, and 4g below). | Steps 4, 5 |
| Q8 | The Grafana group id for `grafana_uid`/`grafana_gid` in the backup config is not stated. The compose file sets `user: "472"` (VERIFIED) and the example says `grafana_gid = 0`. Read it with `docker exec grafana id`. | Step 2 |
| Q9a | How does the dedicated service account get Docker access for `docker cp` and `docker exec`? Docker group membership is root-equivalent; the safer option is a root-owned wrapper allowed by one exact `sudoers` rule. This doc does not choose. | Steps 0c, 2 |
| Q10 | How is a P1 produced on demand to test the email route end to end? No doc says. | Step 5 |
| Q12 | ANSWERED (owner decision 2026-11-20, issue #157). The limits live in the watch (it refuses a body over 16 KB, waits 2 s between posts, posts at most 15 per run) and in the router's `Check Expiry Secret` node (it denies a body over 16 KB, a call under 1 s after the last accepted one, and more than 30 accepted calls in 10 minutes). See `docs/expiry-watch.md`, "Request limits". | Step 6 |

## Order and why

The order puts read-only checks first, the safety net second, cleanup third,
and every Grafana restart before anything that depends on it. The request's
item numbers are in the last column.

| Step | What | Risk | Depends on | Request item |
|------|------|------|-----------|--------------|
| 0 | Preflight, 0a: put the repo on the box, 0b: one dev config for every new Grafana value (0b.5: the read-only token and wrapper the box uses to read it), 0c: the service account | low | nothing | |
| 1 | Read the heartbeat ping log | none, read only | heartbeat deployed | 1 |
| 2 | First live backup and restore rehearsal | low | step 0 | 4 |
| 3 | Delete the FAILTEST workflow and credential | low, irreversible | step 2 (a backup exists) | 2 |
| 4 | Notification failure alert rule | medium, restarts Grafana | steps 1, 2 | 3 |
| 5 | P1 email contact point | medium, restarts Grafana | step 4 (one restart at a time) | 6 |
| 6 | Expiry watch, dry run then schedule | low until it posts | steps 1, 5 | 5 |
| 7 | Game-day scenarios, dry run only | none | steps 1, 4 | 7 |
| 8 | Enable Pushover; mute before and unmute after the live tests | medium, pages a real phone | step 5 (so test pages do not collide) | 9 |
| 9 | Deactivate the old router after a day of traffic | medium | steps 1 and 24 hours of normal traffic | 8 |
| 10 | Game-day live runs | high, breaks things on purpose | steps 2, 4, 8, 9 | 7 |

Why this order:

- The backup (step 2) comes before any change to n8n or Grafana, so every later
  rollback has an archive to fall back to. It also holds the n8n credential
  store that step 3 deletes from.
- Steps 4 and 5 each restart Grafana. Do them one after the other with a check
  in between, so a bad file is traced to one change.
- Game-day live runs (step 10) wait for the old router to be gone (step 9),
  because breaking the alert path during the "normal traffic" day would spoil
  that evidence, and the `router-inactive` scenario needs the real router id.
- Pushover (step 8) is enabled before game-day runs, which send real phone
  messages, and after the email test in step 5, whose test P1 would otherwise
  also page the phone.

## Step 0. Preflight (LIVE, read only)

Source: `docs/live-deploy-runbook.md`, sections 1 and 2.

Prerequisites: the stack is running; `siem-run` and its token file exist
(runbook section 2); a copy of this repo exists at `REPO_DIR` on LOGGING_BOX
(step 0a, which you do first; every command below that says `cd REPO_DIR` fails
without it).

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker ps --format "{{.Names}}" | sort'
```

Expected: the n8n, grafana and influxdb containers are listed (VERIFIED:
runbook section 1 check).

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-setup-alert-router.py --check; echo "exit code: $?"'
```

Expected: three lines `... : present` and `exit code: 0` (VERIFIED: runbook
section 2). `siem-run: token file missing or unreadable` means section 2 of that
runbook is incomplete.

Then do step 0b before steps 4 and 5.

Rollback: nothing changed.

## Step 0a. Put the repo on the box (LIVE, do this first)

Why: `/opt/siem` on LOGGING_BOX is the deployed stack. It has no `n8n` folder and
no `scripts/live-deploy` folder, so the router import, the test script, the
backup, the expiry watch and the example files named below do not exist there.
`REPO_DIR` must be created. `scripts/live-deploy/*.py` import
`scripts/container_engine.py` from the folder above them, so copying only
`live-deploy` breaks them: copy the whole `scripts` folder.

Pick `REPO_DIR`. The suggestion is `/opt/siem-repo`: root owned and readable by
everyone, so the jobs of step 0c (which run as `SERVICE_ACCOUNT`) can read it and
cannot change the code they run. A path under a home directory fails for that
account when the home directory is mode 700. It holds no state and no secret.

On your workstation, in a clone of this repository (the fetch makes sure
`origin/master` is current; the last command prints the commit the archive was
made from, so you can record it):

```
git fetch origin && git rev-parse --short origin/master
git archive --format=tar.gz --prefix=siem-docker-stack/ -o "$HOME/siem-repo.tar.gz" origin/master scripts n8n docs docker/grafana/provisioning/alerting
gzip -dc "$HOME/siem-repo.tar.gz" | git get-tar-commit-id
sha256sum "$HOME/siem-repo.tar.gz"
scp -i KEY_FILE -o IdentitiesOnly=yes "$HOME/siem-repo.tar.gz" LOGGING_BOX:
rm -f "$HOME/siem-repo.tar.gz"
```

The `sha256sum` line prints the checksum of the archive ON YOUR WORKSTATION. That
64-character value is `EXPECTED_SHA256`. It must come from the workstation, never
from the box and never from a file that travelled with the archive: a checksum that
travels with the archive proves nothing against whoever altered the archive. The
commit id from the line above is the record of what it should contain.

Then unpack it on LOGGING_BOX. The design is a release folder per upload and one
symbolic link: `/opt/siem-repo` (this is `REPO_DIR`) is a symlink to
`/opt/siem-repo-releases/TIMESTAMP`. Going live means replacing the symlink with ONE
rename (`mv -T` of a new symlink onto the old one, a single `rename(2)`), so the path
`/opt/siem-repo` always resolves to a complete tree, the old one or the new one, and
a failure at any step leaves the old link untouched. Nothing is ever deleted or
renamed aside, so there is no restore step that could itself fail. Paste
`EXPECTED_SHA256` into the command by hand. `git archive` records group-writable
modes (directories 775, files 664) and `tar` keeps them, so the steps below remove
group and other write permission explicitly, refuse any symlink and any remaining
writable entry, and only then flip the link. `--strip-components=1` drops the
`siem-docker-stack/` prefix. If staging fails, only the new release folder (which has
a unique name made in this command) is removed. If `/opt/siem-repo` is a real
directory (from an earlier version of this runbook) the command stops without doing
anything; migrate once by hand while nothing uses it:
`sudo mkdir -p /opt/siem-repo-releases && sudo mv /opt/siem-repo /opt/siem-repo-releases/legacy`
and then `sudo ln -s /opt/siem-repo-releases/legacy /opt/siem-repo` (that one-time
migration is the only place with a window, and the unused first install has none). A
leftover `/opt/siem-repo.new` directory from an earlier run is not used any more:
`sudo rm -rf /opt/siem-repo.new` removes it.

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd "$HOME" && TS="$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N4 -tx1 /dev/urandom | tr -d " \n")" && RL=/opt/siem-repo-releases && NEW="$RL/$TS" && CREATED="" && printf "%s  siem-repo.tar.gz\n" EXPECTED_SHA256 | sha256sum -c - && { ! sudo test -e /opt/siem-repo || sudo test -L /opt/siem-repo || { echo "STOP: /opt/siem-repo is a real directory; migrate it once by hand (see the text above)"; false; }; } && sudo install -d -m 755 -o root -g root "$RL" && sudo test ! -e "$NEW" && sudo mkdir -m 755 "$NEW" && CREATED="$NEW" && { { sudo tar -xzf siem-repo.tar.gz -C "$RL/$TS" --strip-components=1 --no-same-owner --no-same-permissions && sudo chmod -R go-w "$RL/$TS" && test -z "$(sudo find "$RL/$TS" -perm /022 -o -type l)" && sudo test -f "$RL/$TS/scripts/live-deploy/siem-run"; } || { echo "STAGING FAILED: the live link is untouched"; if [ -n "$CREATED" ] && [ "$(sudo readlink -f "$CREATED")" != "$(sudo readlink -f /opt/siem-repo)" ]; then echo "removing only the release this run created: $CREATED"; sudo rm -rf "$CREATED"; else echo "not removing $CREATED (not created by this run, or it is the live release)"; fi; false; }; } && PREV="$(sudo readlink /opt/siem-repo || true)" && sudo rm -f /opt/siem-repo.next && sudo ln -s "$RL/$TS" /opt/siem-repo.next && sudo mv -T /opt/siem-repo.next /opt/siem-repo && [ "$(sudo readlink /opt/siem-repo)" = "$RL/$TS" ] && echo "LIVE: $RL/$TS (previous: ${PREV:-none})" && sudo find -L /opt/siem-repo -perm /022 | wc -l && ls /opt/siem-repo/scripts/live-deploy /opt/siem-repo/n8n'
```

Expected: `OK` from the checksum, then `LIVE: /opt/siem-repo-releases/TIMESTAMP
(previous: ...)` (this line is the read-back that proves which tree is live: it is
the link's own target), `0` (no entry is writable by group or others), and the
listings of the `live-deploy` scripts (including `siem-run`) and of `n8n`
(`grafana-alert-router.json`). Any other output means the link was not changed.
Note the `previous:` value: that is the rollback target. Prove which tree is live at
any time with `readlink /opt/siem-repo`. Delete the archive on the box
(`rm -f "$HOME/siem-repo.tar.gz"`). A release folder is named
`UTC-TIMESTAMP-RANDOMHEX` (seconds plus 8 random hex digits), is created with a plain
`mkdir` that fails if the name exists, and the command refuses to go on in that case,
so two runs in the same second can never share or clean up each other's folder; the
cleanup after a failed staging removes only the folder this very run created and
never the one the live link points to. Old releases accumulate: prune them with the
step below, never by hand. Here `REPO_DIR` is `/opt/siem-repo`;
substitute it in every command below. To update later, repeat both blocks.

Rollback: flip the link back to the `previous:` release with the same single rename.
The command validates the target BEFORE the rename, because a typo would otherwise
install a dangling link: it must be a plain absolute path of safe characters, a real
directory (not a symlink), directly under `/opt/siem-repo-releases` after
`realpath`, not the current live release, and it must contain the repository marker
files. It refuses with a message otherwise and changes nothing; after the rename it
reads the link back and checks the tree is reachable. Put the path in the quotes
(`PREVIOUS_RELEASE_DIR` is the `previous:` path printed above):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'P="PREVIOUS_RELEASE_DIR" && RL=/opt/siem-repo-releases && case "$P" in ""|*[!A-Za-z0-9._/-]*) echo "REFUSING: the path is empty or has unsafe characters"; false;; esac && case "$P" in "$RL"/*) true;; *) echo "REFUSING: $P is not under $RL"; false;; esac && sudo test -d "$P" && ! sudo test -L "$P" && R="$(sudo realpath -e "$P")" && [ "$R" = "$P" ] && [ "$(dirname "$R")" = "$RL" ] && sudo test -f "$P/scripts/live-deploy/n8n-setup-alert-router.py" && sudo test -f "$P/n8n/grafana-alert-router.json" && [ "$(sudo readlink -f /opt/siem-repo)" != "$P" ] && sudo rm -f /opt/siem-repo.next && sudo ln -s "$P" /opt/siem-repo.next && sudo mv -T /opt/siem-repo.next /opt/siem-repo && [ "$(sudo readlink /opt/siem-repo)" = "$P" ] && sudo test -f /opt/siem-repo/scripts/live-deploy/n8n-setup-alert-router.py && echo "ROLLED BACK: live is now $(sudo readlink /opt/siem-repo)" || { echo "ROLLBACK NOT DONE: a check failed; the live link is unchanged unless it was the last read-back that failed, so run: readlink /opt/siem-repo"; false; }'
```

If it prints `ROLLBACK NOT DONE`, read which message came before it (`REFUSING`, or
no message when the directory, a marker file or the not-current check failed) and fix
the path; nothing was changed. On a first install there is nothing to go back to:
`sudo rm -f /opt/siem-repo`. Nothing else changed. The archive holds only repository
files, no secret value and no live address.

Prune old releases (needed over time: every update adds a release and nothing else
removes one). The function below keeps the live release, the previous release you
give it, and the newest N other releases, and lists as candidates only folders under
`/opt/siem-repo-releases` whose names have the release shape
`YYYYMMDDTHHMMSSZ-8hex` (so `legacy` and anything else are never touched), that are
real directories (not symlinks), and that are neither the live nor the previous
release. The default is a dry run that only lists; `apply` removes the candidates,
re-checking each one against the live link right before its removal. DECIDED
2026-11-20 (owner: "3 others"): N is 3, so at most live + previous + 3 releases stay;
the size of one release is a few MB, so this is about safety margin, not disk. In a session (the
session variables block has been pasted, and `OWNER_FRESH` is `1`):

```
owner_prune_releases() {
  : "runbook-block-prune-v3"
  local N="$1" PREV="$2" MODE="${3:-dry-run}" RL=/opt/siem-repo-releases LIVE D B KEPT=0 I
  local -a L
  case "$N" in ''|*[!0-9]*) echo "STOP: N must be a whole number"; return 1;; esac
  LIVE="$(sudo readlink -f /opt/siem-repo)" && [ -n "$LIVE" ] && sudo test -d "$LIVE" || { echo "STOP: the live release cannot be resolved"; return 1; }
  if [ -n "$PREV" ]; then PREV="$(sudo readlink -f "$PREV")" || { echo "STOP: the previous release cannot be resolved"; return 1; }; fi
  L=("$RL"/*/)
  for (( I=${#L[@]}-1; I>=0; I-- )); do
    D="${L[$I]%/}"; B="${D##*/}"
    [[ "$B" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]] || continue
    [ -L "$D" ] && continue
    if [ "$D" = "$LIVE" ]; then echo "keep (live): $D"; continue; fi
    if [ -n "$PREV" ] && [ "$D" = "$PREV" ]; then echo "keep (previous): $D"; continue; fi
    KEPT=$((KEPT+1))
    if [ $KEPT -le "$N" ]; then echo "keep (newest $N): $D"; continue; fi
    echo "candidate: $D"
    if [ "$MODE" = apply ]; then
      if [ "$(sudo realpath -e "$D")" = "$D" ] && [ "$D" != "$(sudo readlink -f /opt/siem-repo)" ] && sudo rm -rf -- "$D"; then echo "removed: $D"; else echo "STOP: refused to remove $D"; return 1; fi
    fi
  done
  return 0
}
OWNER_SUM_PRUNE="$(declare -f owner_prune_releases | sha256sum | cut -d' ' -f1)"
```

First the dry run (lists only; `PREVIOUS_RELEASE_DIR` as above, or an empty string if
there is none), then, after reading the candidates, the apply:

```
if [ "$OWNER_FRESH" = 1 ] && [ "$(declare -f owner_prune_releases | sha256sum | cut -d' ' -f1)" = "$OWNER_SUM_PRUNE" ]; then owner_prune_releases 3 "PREVIOUS_RELEASE_DIR"; else echo "STALE FUNCTION: open a fresh bash shell, set the session variables and paste again"; false; fi
if [ "$OWNER_FRESH" = 1 ] && [ "$(declare -f owner_prune_releases | sha256sum | cut -d' ' -f1)" = "$OWNER_SUM_PRUNE" ]; then owner_prune_releases 3 "PREVIOUS_RELEASE_DIR" apply; else echo "STALE FUNCTION: open a fresh bash shell, set the session variables and paste again"; false; fi
```

## Step 0b. One dev config for every new Grafana value (LIVE)

Owner decision: all values the Grafana restart needs live in ONE dev config of
the `homelab` Doppler project, and the restart reads only that config. That
config holds the new SMTP values (step 5), the failure webhook URL (step 4) and a
copy of `GRAFANA_WEBHOOK_SECRET`. The copy is needed because Compose refuses to
start Grafana without that variable (VERIFIED: `docker/docker-compose.yml`
requires it non-empty). `prd_network` is not changed by anything in this step or
in steps 4 and 5: it is only read, once, to make the copy.

The config is named `dev_network` (owner decision), a branch config under the
`dev` environment of project `homelab`. It does not exist yet; item 1 creates
it. The configs in `homelab` before this step are `dev`, `dev_personal`, `prd`,
`prd_network` and `stg` (read with `doppler configs --project homelab` on
2026-11-19). Do not use any prd config.

Prerequisites: Doppler CLI logged in on the machine where you run these
commands, with access to project `homelab`.

1. Create `dev_network` and confirm it exists. Flags VERIFIED from
   `doppler configs create --help`, run 2026-11-19: `--environment/-e`,
   `--project/-p`, and the name as a positional argument or `--name`. INFERRED:
   the naming rule for branch configs (the name starts with the environment
   name, here `dev`); if Doppler refuses the name, stop and report the message.

```
doppler configs create dev_network --project homelab --environment dev
doppler configs --project homelab
```

   The second command lists the configs; `dev_network` must appear next to the
   five existing ones, and nothing existing changes. It holds no secrets yet.

   Rollback for this item: delete it only while it is empty. First confirm it is
   empty (`--only-names` is VERIFIED from `doppler secrets --help`, 2026-11-20):

```
doppler secrets --only-names --project homelab --config dev_network
```

   Then delete it. Flags VERIFIED from `doppler configs delete --help`, run
   2026-11-19: the config as a positional argument or `--config/-c`,
   `--project/-p`, and `--yes/-y` to skip the confirmation (leave `--yes` off to
   be asked):

```
doppler configs delete dev_network --project homelab
```

   Once later steps have put secrets in it, deleting it destroys them; use the
   per-step rollbacks instead.

2. Copy the webhook secret value from `prd_network` into the dev config without
   ever printing it. Doppler's own output goes straight into the second command
   on stdin. `doppler secrets set` echoes the value by default, so the second
   command carries `--silent` and also ends in `> /dev/null` (both, on purpose):

```
doppler secrets get GRAFANA_WEBHOOK_SECRET --plain --project homelab --config prd_network | doppler secrets set GRAFANA_WEBHOOK_SECRET --project homelab --config dev_network --silent > /dev/null
```

   Method status, from Doppler's documentation read 2026-11-19
   (docs.doppler.com: accessing-secrets, setting-secrets, secrets-setup-guide,
   and the CLI pages):

   - VERIFIED: `doppler secrets get NAME --plain` prints the value alone
     (accessing-secrets, "Getting Values").
   - VERIFIED: `doppler secrets set NAME` accepts the value on piped stdin
     (setting-secrets: "interactive mode, key-value pairs, or stdin", with the
     example `cat file | doppler secrets set TLS_CERT`). The stdin form with
     `> /dev/null` is also used in `docs/update-alerting.md` (webhook
     authentication, step 1).
   - VERIFIED: `set` echoes the value by default and `--silent` suppresses it
     (setting-secrets). Every `doppler secrets set` in this runbook carries
     `--silent` and ends in `> /dev/null`. The CLI's own help describes
     `--silent` only as "disable output of info messages" (read from
     `doppler secrets set --help` 2026-11-20), so the `> /dev/null` is the part
     you rely on; keep both.
   - VERIFIED (CLI help, run 2026-11-20): `doppler secrets get` and `doppler
     secrets set` both take `--project/-p` and `--config/-c`; `get` has
     `--plain`; `doppler secrets` has `--only-names`; `doppler configs create`
     and `delete` take the flags used in item 1. Confirm again with `--help` if
     your CLI version differs.
   - NOT DOCUMENTED: whether `--plain` prints a trailing newline, and how `set`
     treats a trailing newline on stdin. That is why the check in item 3 is
     required, not optional.

   If the second command errors, stop and report; do not fall back to typing the
   value.

3. Required check of the copy, printing only `same` or `differs`, never a value
   (flags are VERIFIED per item 2):

```
test "$(doppler secrets get GRAFANA_WEBHOOK_SECRET --plain --project homelab --config prd_network | sha256sum | cut -d' ' -f1)" = "$(doppler secrets get GRAFANA_WEBHOOK_SECRET --plain --project homelab --config dev_network | sha256sum | cut -d' ' -f1)" && echo same || echo differs
```

Expected: `same`. If it prints `differs`, the likely cause is a trailing newline
added or kept by one of the two commands. Stop and report it. Do not use the
copy, do not start the Grafana restart in steps 4 and 5 with it, and do not
try to fix it by typing or printing the value. Delete the dev copy (see
Rollback below) until it is resolved.

4. Find out which other variables the Grafana restart needs, BEFORE steps 4 and
   5 restart it from this one config. `docker compose up -d grafana` reads the
   whole compose file, and `docker/docker-compose.yml` requires, with no default,
   `GRAFANA_ADMIN_PASS`, `WAZUH_GRAFANA_RO_PASSWORD`, `OPENSEARCH_READONLY_PASSWORD`,
   `GRAFANA_INFLUX_PASSWORD`, `PROMETHEUS_GRAFANA_PASSWORD`,
   `PROMETHEUS_OTLP_GRAFANA_PASSWORD`, `INFLUXDB_ADMIN_PASSWORD` and more (list them
   all with the first command below, which prints names only). Variables that have a
   default, such as `SIEM_HOST` (it sets `GF_SERVER_ROOT_URL`), `GRAFANA_ADMIN_USER`
   and `BIND_ADDR`, silently fall back to the default when they are missing: a
   restart that lacks `SIEM_HOST` changes Grafana's root URL. Where these values come
   from today (an `.env` file in `/opt/siem` that Compose reads on its own, or the
   shell) is not in a repo doc (OPEN QUESTION). Compose reads `/opt/siem/.env` in
   addition to the shell, and a `doppler run` value wins over `.env`, so an `.env`
   that already holds them is enough (INFERRED from Compose's precedence rules).
   Read-only checks, names only, never a value. The `.env` file may be readable
   by root only, so it is read with `sudo`; the `sed` prints a key only when a
   line is an assignment, and replaces the whole line with that key, so no value
   is ever printed. The three lists are: every name the compose file
   interpolates, the names `.env` supplies, and the names Doppler holds:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'grep -oE "[$][{][A-Za-z0-9_]+" /opt/siem/docker-compose.yml | cut -c3- | sort -u'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'ls -l /opt/siem/.env; sudo sed -n -E "s/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=.*/\2/p" /opt/siem/.env | sort -u'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'comm -23 <(grep -oE "[$][{][A-Za-z0-9_]+" /opt/siem/docker-compose.yml | cut -c3- | sort -u) <(sudo sed -n -E "s/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=.*/\2/p" /opt/siem/.env | sort -u)'
doppler secrets --only-names --project homelab --config dev_network
```

   The third command prints the names the compose file uses that `.env` does NOT
   supply (it needs `bash` as the remote login shell, INFERRED). Every name in
   that output must appear in the fourth command's list (the Doppler output format
   is NOT verified here, so compare by eye); any name missing from both must be
   added to `dev_network` (copy it from `prd_network` the way item 2 does, one at
   a time, with the item 3 check) before any Grafana restart. If the second command
   shows no `.env` (`No such file`), every name in the first list must be in
   Doppler. If you cannot establish this, do not restart Grafana: OWNER DECISION,
   check each name by hand with the commands above and record the result in your ops
   notes. If the restart fails with a `set NAME` message, the container is
   unchanged: add that name and retry.

Watch: the output of item 2 is empty, and no secret value appears anywhere in
the terminal or scrollback.

Note that the copy now holds a shared secret in two configs. `docs/update-alerting.md`
says the secret must be unique to the router contact point and never reused for
other services; this is the same contact point, and the owner chose it. Rotate
both together (VERIFIED: "Rotate by changing the Doppler value and the n8n
credential together"; add the dev copy to that list).

Rollback: delete `GRAFANA_WEBHOOK_SECRET` from the dev config in Doppler. Nothing
in `prd_network` was changed, and the live Grafana is unaffected until step 4d.

### 0b.5 The box reads `dev_network` through a read-only token (issue #177)

Owner decision (2026-11-20, "Read-only service token in a mode 600 file"): every
Grafana restart and every n8n recreate in this runbook reads `dev_network` on
LOGGING_BOX through the wrapper `scripts/siem-net-run`, which holds a read-only
Doppler service token. It does the same job for `dev_network` that `siem-run`
does for the old token (`docs/live-deploy-runbook.md`, section 2). Nothing else
logs in on the box.

Flags below are VERIFIED from the installed Doppler CLI, v3.77.1,
`doppler configs tokens create --help` and `doppler configs tokens revoke --help`,
read 2026-11-20, and from https://docs.doppler.com/docs/service-tokens (read
2026-11-20: a service token is limited to a single config of one project;
revoking is permanent and takes effect at once). Anything not in those two sources
is marked INFERRED.

What the token is allowed to do, each scope and why:

- project `homelab`, config `dev_network`, and no other config: the only values
  the restarts need are the ones in step 0b. A token for `prd_network` or any prd
  config is never used here.
- access `read` (the CLI default; the other choice is `read/write`, which this
  runbook refuses): the box only reads values into one child process. It never
  creates, changes or deletes a secret, so a stolen token cannot change anything.
- no `--max-age`: the box needs it on every restart, so it does not expire by
  itself. The way to end it is the revoke below.

Which values a command receives is a separate limit, set by the wrapper, not by the
token. The wrapper REFUSES to run without `--require NAME1,NAME2` and/or
`--optional NAME3,NAME4` followed by `--`, and injects exactly those names and
nothing else (`--only-secrets`, VERIFIED: `doppler run --help`, 2026-11-20).
Without that, every secret in `dev_network` would be added to the command's
environment after the wrapper cleaned it, so a secret named `LD_PRELOAD`,
`BASH_ENV`, `PATH`, `ZDOTDIR`, `RUSTC_WRAPPER` or `DOCKER_HOST` could run code or
redirect Docker. A list of bad names is never complete, so the wrapper holds a
fixed table of the only names it will ever inject (the n8n heartbeat and expiry
names, the names the grafana service of `docker/docker-compose.yml` uses, and the
eight lines added by hand in 4b and 5b; a test computes the table from those
sources, so it cannot drift) and refuses any other name with exit 2. Adding a
name means changing `scripts/siem-net-run`, which is a reviewed change.

`--require` names must exist and be non-empty in `dev_network`: the wrapper clears
every requested name from its own environment first (so a copy you exported in your
shell cannot stand in for a missing secret), runs the command only after a checker
has found each required name non-empty, and otherwise stops with exit 3 and
`required secret NAME is missing or empty`. `--optional` names are injected when
`dev_network` holds them and are simply absent when it does not (some of Grafana's
values still live in `/opt/siem/.env`, and `docker compose` itself refuses a
required value that is missing). Each operation below carries its own lists: the
n8n recreate requires every name its compose file takes; the step 4 restarts
require `GRAFANA_WEBHOOK_SECRET` and `DISCORD_FAILURE_WEBHOOK_URL` (stored in 0b and
4a); the step 5 restart also requires the seven values of 5a.

What the wrapper does and does not protect. It does protect: the command and its
children do not inherit the token (the Doppler service token; the wrapper's first step inside
`doppler run` drops it, because `doppler run` copies its own environment into the
child; VERIFIED by the Daybreak review of the CLI source, not by a live run), and
they receive only the named secrets. It does NOT protect against hostile code
running as your user on the box: the `doppler` process, the parent of the
command, still holds the token, and the token file is readable by your user by
design. It is not a sandbox. (The alternative of storing the token in the CLI's own
config does not help: `doppler configure set token=...` takes the token on the
command line, and the installed CLI v3.77.1, run 2026-11-20 on a throwaway
folder, stored a `secret-...` reference rather than the token in the file, which
points at the system secret store, not at the private folder.)

Every one of the 25 names in the wrapper's table is in exactly one of the two tables
below (a test checks this against the script).

Secret values (who must never see them). These are credentials; a leak lets the
holder act as the service named. Keep them out of logs, tickets and chat; only the
named consumer needs them.

| Name | Who must never see it |
|------|-----------------------|
| `GRAFANA_ADMIN_PASS` | anyone but the Grafana administrator: it is the admin login |
| `GRAFANA_WEBHOOK_SECRET` | anyone outside Grafana and the n8n router credential: it authenticates alert posts to the router |
| `EXPIRY_WATCH_ROUTER_TOKEN` | anyone outside the expiry watch and the n8n router: it authenticates expiry notices |
| `GF_SMTP_USER`, `GF_SMTP_PASSWORD` | anyone outside Grafana and the mail provider: they send mail as you |
| `GRAFANA_INFLUX_PASSWORD`, `OPENSEARCH_READONLY_PASSWORD`, `WAZUH_GRAFANA_RO_PASSWORD` | anyone outside Grafana and that datasource: read access to the logs and metrics |
| `PROMETHEUS_GRAFANA_PASSWORD`, `PROMETHEUS_OTLP_GRAFANA_PASSWORD` | anyone outside Grafana and Prometheus: read access to metrics (a changed destination in the next table would present them to another party) |

Routing and destination values. The table only stops a name from becoming a
process-control variable. A WRONG VALUE of a name that is meant to be injected
still takes effect at the next restart, so these 15 names, which decide where
something connects, who receives what, or what runs, matter beyond being secrets:

| Name | A wrong value does this |
|------|-------------------------|
| `P1_EMAIL_TO` | P1 alert and resolution mail goes to another recipient (alert content leaves to an address you do not control) |
| `GF_SMTP_ENABLED` | email delivery is switched off (P1 mail silently stops) or on |
| `GF_SMTP_STARTTLS_POLICY` | a weaker policy sends the SMTP login and mail without enforced transport encryption |
| `GF_SMTP_FROM_ADDRESS` | the asserted sender of alert mail changes (spoofing, or the provider rejects it) |
| `HEARTBEAT_KIND` | selects another observer integration; the heartbeat goes to the wrong kind of service |
| `GRAFANA_ADMIN_USER` | the Grafana administrator account name changes, and with it which account the admin password belongs to |
| `BIND_ADDR` | Grafana is published on another interface (default `127.0.0.1`), possibly reachable from the network |
| `GRAFANA_PORT` | Grafana moves to another host port; links and probes miss it |
| `GRAFANA_VERSION` | selects the Grafana image tag: an unwanted version, including a downgrade |
| `SIEM_HOST` | the root URL Grafana puts in alert links and mail points at another host |
| `GF_SMTP_HOST` | Grafana presents `GF_SMTP_USER` and `GF_SMTP_PASSWORD` to that SMTP server and sends mail through it |
| `DISCORD_FAILURE_WEBHOOK_URL` | the failure alerts, and their text, go to another destination |
| `HEARTBEAT_PING_URL` | the heartbeat ping goes elsewhere (the observer reports down), or the ping URL leaks to another party |
| `GRAFANA_INFLUX_USER`, `WAZUH_GRAFANA_RO_USER` | the account name Grafana uses for those datasources; a wrong name fails or uses a different account |

Who can change these is whoever has write access to `dev_network` in project
`homelab`: Doppler members with write access to that config. This document does not
claim that equals access to the compose file on the box; the two are different sets
of people. Check it, then restrict it to you: read the membership and role of
project `homelab` in the Doppler dashboard (send a screenshot if unsure; the screen
is not described here), and review who changed values with `doppler activity`
(the command exists in the installed CLI, VERIFIED `doppler --help`, 2026-11-20; what
its log shows per change is NOT verified here). Doppler's own record of who has
access is the source; nothing in this repository proves it.

OWNER DECISION: keep these routing values in `dev_network` (current), where a
Doppler editor can change them and the next restart applies the change; or keep them
in the root-owned `.env` next to the compose file, so only a root-capable user of the
box can change them (then they leave the table, the `--optional` lists and 4b/5b, and
`docker compose` reads them from `.env`). Nothing has been moved: decide, and the
change is made in a follow-up.

You need, on your own machine (where the Doppler CLI is logged in as you), the
right to create service tokens on that config. Creating the token is the
only step that touches Doppler; the box needs no login of its own.

1. Put the wrapper and the private folder on the box (the folder is mode 700, and
   `siem-net-run` refuses a folder that others can write):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'install -d -m 700 "$HOME/.config/doppler-siem-net" && install -d -m 755 "$HOME/bin" && install -m 755 REPO_DIR/scripts/siem-net-run "$HOME/bin/siem-net-run" && ls -ld "$HOME/.config/doppler-siem-net" "$HOME/bin/siem-net-run"'
```

   The same items 2 to 5 create the first token and rotate a later one. Nothing
   ever overwrites the live token before the new one has been shown to work.

2. Create the new token in a staging folder next to the live one. The `--plain`
   output goes straight into a pipe to the box, where `umask 077` makes the new file
   mode 600 before the first byte is written. It never reaches your terminal, so it
   is never echoed. There is no `-t` on this ssh on purpose (the pipe carries the
   token); the line after it prints the status of both ends, and `0 0` means both
   worked. On a rotation, first list the tokens and write down the old token's slug
   (INFERRED: the list shows names and slugs, not values):

```
doppler configs tokens --project homelab --config dev_network
set -o pipefail
doppler configs tokens create siem-net-box --project homelab --config dev_network --access read --plain | ssh -i KEY_FILE -o IdentitiesOnly=yes LOGGING_BOX 'rm -rf "$HOME/.config/doppler-siem-net.new" && install -d -m 700 "$HOME/.config/doppler-siem-net.new" && umask 077 && cat > "$HOME/.config/doppler-siem-net.new/token"'
echo "exit codes: ${PIPESTATUS[0]} ${PIPESTATUS[1]}"
set +o pipefail
```

3. Read back the owner and mode of the staged file without printing the token
   (expect your user, `600`, and `non-empty`):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'stat -c "%U %a %n" "$HOME/.config/doppler-siem-net.new/token" && if [ -s "$HOME/.config/doppler-siem-net.new/token" ]; then echo non-empty; else echo EMPTY; fi'
```

   `EMPTY` or an error means item 2 failed before the token arrived: run it again.
   The live token has not been touched.

4. Prove the staged token reaches `dev_network`, through the wrapper with a
   read-only call that prints a presence line and never a value:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'SIEM_NET_CONFIG_DIR="$HOME/.config/doppler-siem-net.new" "$HOME/bin/siem-net-run" --require GRAFANA_WEBHOOK_SECRET -- echo "GRAFANA_WEBHOOK_SECRET present"; echo "exit code: $?"'
```

   Expect `GRAFANA_WEBHOOK_SECRET present` and `exit code: 0` (INFERRED: the wrapper
   and the real Doppler CLI together were not run for this document). A line starting
   `siem-net-run:` says what the wrapper refused: a missing or empty token file, a
   symlink, a file owned by someone else, a file or folder that is not private, or an
   allowlist problem. A Doppler error means the token is wrong: stop here, the live
   token is untouched, and revoke the staged one by slug as below.

5. Only after item 4 passed, move the staged token over the live one in a single
   atomic rename (`mv -T`), remove the staging folder, and read the result back:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'mv -T "$HOME/.config/doppler-siem-net.new/token" "$HOME/.config/doppler-siem-net/token" && rmdir "$HOME/.config/doppler-siem-net.new" && stat -c "%U %a %n" "$HOME/.config/doppler-siem-net/token"; echo "exit code: $?"'
```

Rotate, the last part: after item 5, revoke the OLD token by its slug (the one you
wrote down before item 2), never before. The old token stays revocable by slug until
you do:

```
doppler configs tokens revoke --project homelab --config dev_network --slug OLD_SLUG
```

Revoke (also the whole rollback, with the removal of the box files):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'rm -r "$HOME/.config/doppler-siem-net" && rm "$HOME/bin/siem-net-run"; echo "exit code: $?"'
```

After a revoke the next restart or recreate stops with a Doppler error: that is
the intended result. `siem-net-run` passes `--no-fallback` (VERIFIED: `doppler run
--help`, 2026-11-20: "disable reading and writing the fallback file"), so it
neither writes nor reads an encrypted cache of the values. A Doppler outage or a
network failure therefore stops a Grafana restart or an n8n recreate (it fails
closed) instead of starting a container from old values. The consequence is
deliberate: while Doppler is unreachable from the box, those two operations wait.
The folder is created by item 1 and holds only `token`; if `ls -la` of it shows
anything else, remove it before the first use.

## Step 0c. The dedicated service account for scheduled jobs (LIVE)

Owner decision: a dedicated, non-login system account, placeholder
`SERVICE_ACCOUNT` (suggested name `siem-ops`), runs both scheduled jobs: the state
backup (step 2) and the expiry watch (step 6). Neither runs as a person or as
root by default. Do this before step 2.

Source for the shape: `docs/examples/siem-state-backup.service` (a dedicated
user, `UMask=0077`, and the warning that docker group membership is
root-equivalent) and `docs/expiry-watch.md` ("Scheduling": the job user owns the
config, env file and state file, mode 0600).

### 0c.1 Create the account and its state directory

The flags below were checked against the local `useradd --help` on 2026-11-19
(`--system`, `--no-create-home`, `--shell`, `--home-dir` all exist). That this
combination suits your distribution is INFERRED. In a session on LOGGING_BOX:

```
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --home-dir /var/lib/SERVICE_ACCOUNT SERVICE_ACCOUNT
sudo install -d -m 700 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT /var/lib/SERVICE_ACCOUNT
id SERVICE_ACCOUNT
ls -ld /var/lib/SERVICE_ACCOUNT
```

Expect a `uid=` line with no extra groups, and `drwx------` owned by the
account. The nologin shell path may differ on your system (INFERRED; check
`getent passwd` for what other system accounts use).

### 0c.2 Where files live and who can read them

| What | Where (examples, owner may change) | Who may read | Source |
|------|------------------------------------|--------------|--------|
| Backup archives and their `.manifest.json` | `destination_dir`, for example `/var/lib/SERVICE_ACCOUNT/backups` | root and `SERVICE_ACCOUNT` only (mode 700 directory, files written with `UMask=0077`) | example service unit; `docs/backup-restore.md` (directory must be owned by you and not group or world writable, VERIFIED) |
| Backup config with the age PUBLIC recipients | `/etc/siem-state-backup.toml`, mode 0640 per the example, group `SERVICE_ACCOUNT` so only root and the account read it | root and `SERVICE_ACCOUNT` | example config |
| Expiry watch config, registry and state file | `/etc/expiry-watch`, owned by `SERVICE_ACCOUNT`, mode 700 | `SERVICE_ACCOUNT` (and root) | `docs/expiry-watch.md` |
| Doppler read-only token file | `/var/lib/SERVICE_ACCOUNT/doppler-token`, mode 600 | `SERVICE_ACCOUNT` only | this step |
| The age PRIVATE keys | NOT on LOGGING_BOX | the owner, offline | `docs/backup-restore.md` secret material warning |

The private age key is never on the box and the job never touches it: the backup
uses public recipients only and cannot decrypt (VERIFIED: `docs/backup-restore.md`).
Create the backup directory and set the group on the config:

```
sudo install -d -m 700 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT /var/lib/SERVICE_ACCOUNT/backups
sudo chgrp SERVICE_ACCOUNT /etc/siem-state-backup.toml
sudo chmod 0640 /etc/siem-state-backup.toml
```

(Run the `chgrp` after step 2b creates the config, and set `destination_dir` to
`/var/lib/SERVICE_ACCOUNT/backups` for the SCHEDULED run; both are INFERRED layout
choices.) The backup refuses a `destination_dir` that is not owned by the user
running it (VERIFIED: `scripts/state_backup_lib.py`, "destination_dir is not owned
by the user running the backup"), so the by-hand `sudo` run of step 2c, which runs
as root, cannot use this directory; step 2c says what to do.
`ProtectSystem=strict` in the example unit also needs `ReadWritePaths` to name the
archive directory; edit the unit in step 2e.

### 0c.3 How the account gets its secrets

The owner creates a read-only Doppler service token scoped to the `dev_network`
config only (project `homelab`), in the Doppler dashboard. This doc does not
describe that screen (no repo doc verifies it; send a screenshot if unsure).
Never type the token on a command line, never print it. Store it, read from a
prompt, in a file only the account can read:

```
read -rs -p "Doppler service token: " TOK; echo
printf '%s' "$TOK" | sudo install -m 600 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT /dev/stdin /var/lib/SERVICE_ACCOUNT/doppler-token
unset TOK
sudo ls -l /var/lib/SERVICE_ACCOUNT/doppler-token
```

Expect `-rw-------` owned by the account, and no token in the terminal
(INFERRED: `install` from `/dev/stdin`; this mirrors the token-file pattern in
`docs/live-deploy-runbook.md` section 2, which is VERIFIED for `siem-run`). A
scheduled job then reads it through the Doppler CLI's token variable, for example
`DOPPLER_TOKEN` set from that file inside the unit or wrapper, never written into
the unit text (INFERRED: whether your CLI version takes the token that way;
confirm with `doppler run --help`). A read-only token cannot be used to change
secrets. Rotate it by creating a new token and replacing the file, then revoking
the old one in the dashboard.

### 0c.4 The timers run as this account

The backup unit's `User=` is `SERVICE_ACCOUNT` (the example uses a placeholder
user, VERIFIED). The expiry watch unit or cron entry runs as the same account, so
the config folder in 6a is owned by it. Use whichever of systemd timers or cron
you prefer; a cron entry goes in that account's crontab (`sudo crontab -u
SERVICE_ACCOUNT -e`; INFERRED, a nologin account can still own a crontab).

### 0c.5 Docker access: the owner decides (OPEN QUESTION Q9a)

The backup uses `docker cp` and `docker exec` (VERIFIED: `docs/backup-restore.md`),
so the account needs access to the Docker socket. Plainly: membership of the
`docker` group is root-equivalent, since anyone who can start containers can
mount the host's filesystem (VERIFIED: warning in
`docs/examples/siem-state-backup.service`). Giving a service account that access
means a flaw in the job or a leak of its files becomes a root-level problem.

Two options. This doc does not choose:

- Option 1: add `SERVICE_ACCOUNT` to the `docker` group. Simple, and the
  root-equivalent risk above applies in full. The expiry watch does not need
  Docker and can run without it only if it runs under a different account, which
  contradicts the one-account decision.
- Option 2: keep the account out of the `docker` group and let it run only the
  exact backup command as root through a small root-owned wrapper script and a
  `sudoers` entry that allows that one command and nothing else. Safer. Cost: the
  wrapper and sudoers rule must be written, reviewed and tested (a code and
  config change outside this doc), and the `restore` side is a separate
  decision. The archives would then be written by root unless the wrapper
  drops privileges, which is a design question for that change.

Until the owner answers Q9a, do 0c.1 to 0c.4, and run step 2c by hand with `sudo`
as written; do not schedule the backup (2e) and do not start the expiry watch
timer under a docker-capable account.

Rollback: `sudo userdel SERVICE_ACCOUNT` (INFERRED command name), then remove
`/var/lib/SERVICE_ACCOUNT` once nothing needs the archives, and revoke the
Doppler token in the dashboard. Archives you still need must be copied out first.

## Step 1. Read the Healthchecks ping log (LIVE, read only)

Request item 1. Source: `docs/heartbeat.md` (sections "The three observers",
"Enable it", "Failure behavior").

Prerequisites (all VERIFIED as the enable list in `docs/heartbeat.md`; whether
they are done on the live box is INFERRED until you check):

- Grafana rule "Alert path heartbeat" is deployed and Grafana was restarted.
- The `heartbeat` route is merged into the notification policy tree.
- The updated router workflow is imported and active.
- `HEARTBEAT_PING_URL` and `HEARTBEAT_KIND` are set on the n8n container, with
  `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`.
- The check at the observer has a simple 5 minute period and a grace time of at least 15 minutes
  (it goes down after about 20 minutes of silence, period plus grace; see [heartbeat.md](heartbeat.md) if it shows down while the path is up).

Check the n8n container has the variable, printing presence only, never the
value:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n sh -c "if [ -n \"\$HEARTBEAT_PING_URL\" ]; then echo HEARTBEAT_PING_URL set; else echo HEARTBEAT_PING_URL unset; fi; echo HEARTBEAT_KIND=\${HEARTBEAT_KIND:-healthchecks}"'
```

Then open the check's ping log in the observer's web interface. The docs do not
describe that screen, so this doc does not either (INFERRED: Healthchecks lists
each ping with a timestamp; send a screenshot if it looks different).

Watch:

- Pings arrive every 5 to 6 minutes (VERIFIED: `docs/heartbeat.md`, "How it
  works"; Grafana repeats only at a `group_interval` tick). Over 30 minutes
  expect 5 to 6 pings. A failed ping is now retried up to 3 times, so one ping
  can arrive up to 19 seconds late (VERIFIED: `docs/heartbeat.md`, "Failure
  behavior"); that is not a fault.
- A gap over about 6.5 minutes or two pings closer than 5 minutes is not
  expected; note the times. The observer goes down only after about 20 minutes
  of silence (period 5 plus grace 15), which tolerates about three missed pings.
- No `/fail` pings: those mean a heartbeat with a wrong `phone` label (VERIFIED:
  "Contract failure sends /fail").

If no pings: the doc's list of causes is Grafana down or the rule broken, the
contact point or its header credential wrong, n8n down or the workflow inactive,
the route to the observer broken, or the variable unset (VERIFIED: "What stops
the pings"). Fix by the "Enable it" list, then re-read the log.

Rollback: none needed, this step changes nothing.

## Step 2. First live backup and a restore rehearsal (LIVE)

Request item 4. Source: `docs/backup-restore.md`, section "n8n and Grafana state
backup (issue #83)"; `docs/examples/siem-state-backup.example.toml`; the
`.service` and `.timer` examples next to it.

What this is: an age-encrypted archive of n8n (workflows, credentials still
encrypted by n8n, its encryption key) and the Grafana database (VERIFIED: "What
is and is not covered"). OpenSearch snapshots are a separate job in the first
half of the same doc and are not part of this step.

Prerequisites:

- A machine you trust that is NOT LOGGING_BOX, to hold the age private key
  (VERIFIED: "Keep the age identity off the host that runs the backup, ideally
  offline").
- A place for the archives on LOGGING_BOX (`destination_dir`, default in the
  example `/var/backups/siem-state`).
- Step 0c done, and Q8 answered.
- The documented caveat: no live run of any of this has happened yet, including
  real `age`, `rclone` and the `docker exec` and `docker cp` calls (VERIFIED:
  "Not verified (no live run yet)"). Treat the first run as a test.

### 2a. Make the age keys (on the trusted machine, not LOGGING_BOX)

Make two key pairs so one lost key does not lose the backups (VERIFIED: example
config, "List two or more"). Store the private files offline.

```
age-keygen -o "$HOME/siem-backup-identity-1.txt"
age-keygen -o "$HOME/siem-backup-identity-2.txt"
```

Each command prints `Public key: age1...`. Only the public key goes into the
config. The `.txt` files are the identities (private keys): never copy them to
LOGGING_BOX or into this repo (VERIFIED: config comments; `backup-restore.md`
secret material warning). Copying them onto an offline store is the owner's
choice; the doc says only "offline".

### 2b. Install age and write the config (on LOGGING_BOX)

In a session:

```
sudo apt install age
age --version
sudo cp REPO_DIR/docs/examples/siem-state-backup.example.toml /etc/siem-state-backup.toml
sudo chmod 0640 /etc/siem-state-backup.toml
sudo "${EDITOR:-nano}" /etc/siem-state-backup.toml
```

(The doc says to verify the version after install, INFERRED: any current `age`
works; check the package source.) In the editor set:

- `age_recipients`: the two public keys, one string each. Public keys only; the
  tool rejects secret keys (VERIFIED).
- `destination_dir`: your archive directory.
- `grafana_data_host_dir`: `/data/warm/grafana` (VERIFIED: the compose file
  mounts `/data/warm/grafana` at `/var/lib/grafana`), and `grafana_db_method =
  "auto"` then resolves to `host-sqlite`, the recommended method.
- Restore keys, needed only for a restore but set them now: `helper_image`,
  `grafana_uid = 472` (VERIFIED: compose `user: "472"`), `grafana_gid` (Q8),
  `n8n_uid` and `n8n_gid` (the example shows 1000; INFERRED, check with
  `docker exec n8n id`).
- `rclone_remote` stays commented out until the off-host copy is chosen. An
  off-host copy is recommended by the doc but its tooling is unverified live.

### 2c. First run, by hand

`sudo` runs the backup as root because it needs the container runtime, and the
backup refuses a `destination_dir` that is not owned by the user running it
(VERIFIED: `scripts/state_backup_lib.py`). So for this by-hand run `destination_dir`
must be a root-owned folder, not the `SERVICE_ACCOUNT` folder of step 0c. Create
it and set `destination_dir = "/var/backups/siem-state"` (the example's default)
in the config first:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo install -d -m 700 -o root -g root /var/backups/siem-state && ls -ld /var/backups/siem-state'
```

DECIDED 2026-11-20 (owner: "Service-account-owned folder"): the scheduled runs as
`SERVICE_ACCOUNT` write to `/var/lib/SERVICE_ACCOUNT/backups` (step 0c), owned by that
account, so the config's `destination_dir` changes again when step 2e is done. The
by-hand root run keeps `/var/backups/siem-state`. The Docker access of the scheduled
account is still Q9a; until it is answered, only the by-hand root run exists.

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && sudo python3 scripts/backup-state.py --config /etc/siem-state-backup.toml; echo "exit code: $?"'
```

(The scheduled runs use the dedicated account from step 0c; its Docker access is
Q9a. INFERRED.) Then look at the output directory:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo ls -l /var/backups/siem-state'
```

Watch:

- Exit code 0 and two new files: `siem-state-<UTC timestamp>.tar.gz.age` and
  `<name>.manifest.json` (VERIFIED: "Files written").
- The archive size is more than a few kilobytes (Grafana database plus n8n
  export).
- Any `RECOVERY NEEDED` or Python error text: stop, do not schedule, read
  `docs/backup-restore.md`, "Not verified".
- The `.manifest.json` is advisory only (VERIFIED). Authenticity comes from age.

### 2d. Restore rehearsal (never on production)

Follow the six-step drill in `docs/backup-restore.md` ("Restore drill") on a
scratch machine or a throwaway compose project with a second n8n and Grafana.
Copy the archive and one identity there over a path you trust.

Dry run, which changes nothing (VERIFIED: the doc's command, with your paths):

```
python3 scripts/restore-state.py --config /etc/siem-state-backup.toml --identity "$HOME/siem-backup-identity-1.txt" ARCHIVE_FILE
```

Expect both components listed and checksums ok. Then flip one byte in a copy of
the archive and confirm the dry run aborts. Only on the scratch containers:
`--apply --restore-n8n-key`, then publish workflows, restart n8n, start Grafana
and confirm a credential decrypts and the dashboards and contact point exist
(the doc's drill, steps 4 and 5). Use the second identity for one dry run to
prove it also decrypts. Record the date and result in your ops notes
(VERIFIED: step 6).

### 2e. Schedule it

Only after 2c and 2d pass, and after the Docker access answer in 0c.5 (do not
enable the timer before it). The example unit carries placeholder paths and a
placeholder user. Copy both files, then edit the unit with `sudoedit`: set
`User=` to `SERVICE_ACCOUNT`, `ExecStart=` to
`/usr/bin/python3 REPO_DIR/scripts/backup-state.py --config /etc/siem-state-backup.toml`
(the example's `/opt/siem/scripts/backup-state.py` does not exist on the box),
and `ReadWritePaths=` to the archive directory; set `destination_dir` in the
config to `/var/lib/SERVICE_ACCOUNT/backups`. Then enable the timer:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo cp REPO_DIR/docs/examples/siem-state-backup.service REPO_DIR/docs/examples/siem-state-backup.timer /etc/systemd/system/ && sudoedit /etc/systemd/system/siem-state-backup.service'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo systemctl daemon-reload && sudo systemctl enable --now siem-state-backup.timer && systemctl list-timers siem-state-backup.timer'
```

Expect the timer listed with a next run near 02:30 (VERIFIED: the example timer).
After its first scheduled run, check
`journalctl -u siem-state-backup.service --since today` and the directory.

Rollback: `sudo systemctl disable --now siem-state-backup.timer`; archives are
only files and can be deleted. The config file can be removed. Nothing else on
the stack changed. Keep the identities.

## Step 3. Delete the FAILTEST workflow and its credential (LIVE, irreversible)

Request item 2. Source: `docs/live-deploy-runbook.md`, section 4 (the
failure-path test in a copy, item 6 "Delete the copy") and section 3 (what lives
inside n8n). The name `FAILTEST` itself is in no doc (Q4); use the names you see
in the n8n UI.

Prerequisites:

- Step 2 done: a backup archive exists.
- You can tell the test copy from the real router. The real router is the
  workflow named in `docs/live-deploy-runbook.md` section 3
  ("Grafana SOAR - Alert Router (authenticated)", INFERRED to be the live one;
  Q5) with the credential `grafana-webhook-auth`. The error handler is a
  different workflow with an Error Trigger. Neither may be deleted.
- The test copy has its own webhook path and is not the one Grafana's contact
  point posts to (VERIFIED: the runbook gives the copy "its own webhook path").

Steps, in the n8n web interface (the docs name no menu paths; use the workflow
list and the credentials list as you find them, and send a screenshot if
unsure):

1. List the workflows with their ids (INFERRED command, check
   `n8n list:workflow --help`) and write down the id of the test copy, of the
   live router (`ROUTER_ID`) and of the error handler (`HANDLER_ID`). Tell them
   apart by id, not by name: a duplicate of the router has a similar name.
   Open the test copy in the interface by its id. Confirm it is inactive and that
   its webhook path differs from the live one.

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n n8n list:workflow'
```

2. Delete the workflow (the copy only).
3. Open the credentials list and find the credential made for the failing test
   (for example the deliberately wrong Discord or Pushover credential from the
   test, runbook items 2 and 5). Confirm no other workflow uses it, then delete
   it.
4. Do not touch `grafana-webhook-auth`, `pushover-api`, the Discord webhook
   credential, the router, or the error handler (VERIFIED: runbook section 3).

Read back: run the same `list:workflow` command again. The copy is gone and
`ROUTER_ID` and `HANDLER_ID` are still listed.

Watch: the next heartbeat ping still arrives within 6 minutes (step 1), and no
new error appears in `docker logs --since 10m n8n`.

Rollback: there is no undo in n8n. The test copy has no value; to recreate a
test copy later, duplicate the router and follow runbook section 4. If you
deleted the wrong thing, restore from the step 2 archive on the scratch setup and
re-import the item, or recreate the credentials with
`n8n-setup-alert-router.py --credentials` (VERIFIED: runbook section 3).

## Step 4. Deploy the notification failure alert rule, issue #81 (LIVE)

Request item 3. Source: `docs/notification-failure-alerts.md`; files
`docker/grafana/provisioning/alerting/notification-failure-alert-rule.yml`,
`notification-failure-contact-point.yml.example`,
`notification-failure-notification-policy.yml.example`.

What it does: the rule fires when Grafana's own failed-delivery counter rises,
and routes to a Discord contact point that does not go through n8n (VERIFIED:
"Routing: a different path on purpose").

Prerequisites:

- Step 2 done (backup) and step 1 healthy (so a Grafana restart can be judged).
- A Discord webhook for this purpose, different from the one n8n posts to if
  you can (VERIFIED: contact point example). Created in Discord by you.
- A datasource with uid `prometheus` exists in the live Grafana (VERIFIED in
  `docker/grafana/provisioning/datasources/datasources.yml`; INFERRED for the
  live stack, check the datasource list).
- Step 0b done, and Q7 settled.

### 4a. Store the webhook URL in Doppler dev

In a terminal where the Doppler CLI is logged in. The value is read without
echo and sent on stdin; the command ends in `> /dev/null` because the CLI
echoes values:

```
read -rs -p "Discord failure webhook URL: " VAL; echo
printf '%s' "$VAL" | doppler secrets set DISCORD_FAILURE_WEBHOOK_URL --project homelab --config dev_network --silent > /dev/null
unset VAL
doppler secrets --project homelab --config dev_network --only-names | grep -c DISCORD_FAILURE_WEBHOOK_URL
```

The last line prints `1` when the name exists (the `--only-names` flag is
VERIFIED; the check prints a count, never the value). The `read -rs` plus stdin
approach follows the documented `openssl ... | doppler secrets set ... >
/dev/null` form (VERIFIED: `docs/update-alerting.md`); reading from a prompt is
INFERRED.

### 4b. Pass the variable to Grafana (compose, on LOGGING_BOX)

The compose file does not carry it today (VERIFIED: no `DISCORD_FAILURE` in
`docker/docker-compose.yml`; the example file says it "needs the variable passed
to the grafana service"). In a session, back up and add one line after the
`GRAFANA_WEBHOOK_SECRET` line:

```
cd /opt/siem && B="docker-compose.yml.bak-$(date -u +%Y%m%dT%H%M%SZ)" && [ ! -e "$B" ] && ( umask 077 && cp docker-compose.yml "$B" ) && cmp docker-compose.yml "$B" && [ "$(stat -c %a "$B")" = 600 ] && echo "backup $B ok" && ! grep -q 'DISCORD_FAILURE_WEBHOOK_URL' docker-compose.yml && sed -i '/- GRAFANA_WEBHOOK_SECRET=/a\      - DISCORD_FAILURE_WEBHOOK_URL=${DISCORD_FAILURE_WEBHOOK_URL:-}' docker-compose.yml && grep -n -B1 'DISCORD_FAILURE_WEBHOOK_URL' docker-compose.yml
```

The edit is gated in the same `&&` chain on a backup made by THIS run: the chain
refuses if the backup name already exists, if the copy differs from the live file
or if its mode is not 600, and it prints `backup ... ok` before it touches the
file. It also refuses (and stops) if the line is already present; then skip the
`sed`. The last command shows the new line directly under
`GRAFANA_WEBHOOK_SECRET`. The path `/opt/siem` is the documented default
(`SIEM_DIR`). The backup is mode 600 and never replaces an earlier one (the same
form as `docs/live-deploy-runbook.md`, section 5, step 4); its `ls` line must start
with `-rw-------`. If the last `grep` prints nothing, the live file spells the
line without `=` (the form `      - GRAFANA_WEBHOOK_SECRET` that the live deploy
runbook gives): the `sed` anchor found nothing, so add the line by hand under that
one instead. If the `cp` or the `sed` says permission denied, `/opt/siem` is not
yours to write (INFERRED; step 4c needs `sudo` for the folder below it): repeat
with `sudo`, and keep the backup mode 600.

### 4c. Copy the rule and the contact point

Copy them as their own files so a later `grafana-deploy.py` run, which rewrites
`contact-points.yml`, cannot overwrite them (INFERRED from the script's file
list, Q7):

```
sudo install -m 644 REPO_DIR/docker/grafana/provisioning/alerting/notification-failure-alert-rule.yml /opt/siem/grafana/provisioning/alerting/notification-failure-alert-rule.yml
sudo install -m 644 REPO_DIR/docker/grafana/provisioning/alerting/notification-failure-contact-point.yml.example /opt/siem/grafana/provisioning/alerting/notification-failure-contact-point.yml
ls -l /opt/siem/grafana/provisioning/alerting/
```

(`/opt/siem/grafana/provisioning/alerting/` is the folder the deploy script
writes: VERIFIED in `scripts/live-deploy/grafana-deploy.py` and runbook
section 5.)

### 4d. Restart Grafana and check

Grafana reads provisioning files only at startup (VERIFIED: runbook section 5).
The restart reads only the one dev config from step 0b, through the read-only
token and wrapper of step 0b.5 (owner decision 2026-11-20, resolved; the
wrapper runs `doppler run` for you, a form VERIFIED in `docs/update-alerting.md`,
step 4 of its webhook authentication list, there with `prd_network`). The token
is scoped to `dev_network` by itself, so there is no project or config flag:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd /opt/siem && "$HOME/bin/siem-net-run" --require DISCORD_FAILURE_WEBHOOK_URL,GRAFANA_WEBHOOK_SECRET --optional BIND_ADDR,GF_SMTP_ENABLED,GF_SMTP_FROM_ADDRESS,GF_SMTP_HOST,GF_SMTP_PASSWORD,GF_SMTP_STARTTLS_POLICY,GF_SMTP_USER,GRAFANA_ADMIN_PASS,GRAFANA_ADMIN_USER,GRAFANA_INFLUX_PASSWORD,GRAFANA_INFLUX_USER,GRAFANA_PORT,GRAFANA_VERSION,OPENSEARCH_READONLY_PASSWORD,P1_EMAIL_TO,PROMETHEUS_GRAFANA_PASSWORD,PROMETHEUS_OTLP_GRAFANA_PASSWORD,SIEM_HOST,WAZUH_GRAFANA_RO_PASSWORD,WAZUH_GRAFANA_RO_USER -- docker compose up -d --no-deps grafana; echo "exit code: $?"'
```

(The `SERVICE_ACCOUNT` token of step 0c is for that account's jobs only.)
`siem-net-run: ...` on the first line is the wrapper refusing its token file
(step 0b.5 item 4 lists the causes); nothing was restarted. Compose refusing to start with `GRAFANA_WEBHOOK_SECRET must be set and
non-empty` means the copy in step 0b is missing; the container stays on its old
definition until it is fixed. Any other variable Grafana needs from the old
`prd_network` setup, such as the Pushover or datasource values, must also be in
this config (INFERRED: compare `docker/docker-compose.yml` with the config before
you restart).

Check:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker logs --since 5m grafana 2>&1 | tail -40'
```

Look for provisioning errors naming the two new files. In the Grafana web
interface (Alerting), the folder "Alert Path" holds the rule "Grafana
notification delivery failing" (VERIFIED: rule file), state Normal, and the
contact point `discord-direct` exists. An Error state means the datasource uid
or the metric query is wrong; see 4f.

### 4e. Merge the policy route (manual, the tree is one per organization)

Do not load the `.example` policy file: it replaces the whole tree (VERIFIED:
its header). In Alerting, Notification policies, add one child route with these
values from the example file (VERIFIED): matcher `delivery_failure = true`,
contact point `discord-direct`, group by `alertname` and `integration`, group
wait 30s, group interval 5m, repeat interval 4h. Place it before any route that
matches everything. Do not change the other routes.

### 4f. Prove it can fire (the metric name is UNVERIFIED)

The counter name `grafana_alerting_notifications_failed_total` is unverified,
and it did not exist on the live Grafana on 2026-11-19 because Grafana creates
it after its first failure (VERIFIED: `docs/notification-failure-alerts.md`,
"Unverified: the metric name"). Until you force one failure, the rule is not
proven. The doc's procedure:

1. In Grafana create a temporary contact point of type webhook with URL
   `http://localhost:9/` and use its Test button. Leave the real policy tree
   alone. (That the Test button increments the counter is itself unverified;
   if it does not, point a temporary policy route at it and fire a test alert,
   then remove the route.)
2. Read the counter:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec grafana wget -q -O- http://localhost:3000/metrics | grep notifications_failed'
```

(The doc uses `curl http://grafana:3000/metrics` from a host that can reach it;
the `docker exec wget` form is INFERRED, and the metrics endpoint may need
authentication on your setup.)

3. If the name differs, change the one metric name in query A of the rule file,
   copy it again (4c), restart Grafana (4d).
4. Delete the temporary contact point (and temporary route if used).
5. Then press Test on `discord-direct` and confirm a Discord message arrives.

Watch: after a real or forced failure, the rule goes Pending for 5 minutes then
Firing, and a Discord message arrives in the failure channel (VERIFIED: rule
`for: 5m`).

Rollback (VERIFIED approach, same as `docs/live-deploy-runbook.md` section 5):
delete the policy route; delete the two files from the live alerting folder;
restore `docker-compose.yml.bak-<UTC timestamp>` over the compose file; run the restart
in 4d. n8n and the heartbeat are untouched by this change.

### 4g. Optional: copy the rule file with the deploy script instead of the first line of 4c

PR #126 is merged (commit `862b687`), so the script is in the repo; it reaches
LOGGING_BOX through step 0a. It replaces only the FIRST line of 4c (the rule file):
the `discord-direct` contact point file in the second line of 4c is not on the
script's allowlist and is always copied by hand. The script copies files and
nothing else: it never starts docker and never reads the compose file. It needs
write access to `/opt/siem/grafana/provisioning` as the user who runs it; 4c uses
`sudo` for that folder, so check `ls -ld /opt/siem/grafana/provisioning` first
(INFERRED: if it is root owned, this route does not work as your user, and 4c is
the way). It also needs the `router-path` file of step 6.1 in the helper's config
directory, because it writes the private path into `contact-points.yml`.

Stage the repo files into `SIEM_STAGE_DIR` (default `$HOME/bin/alerting`; the folder
must not be writable by group or others and the files must be mode 644), look at
the plan, then apply:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'mkdir -p "$HOME/bin/alerting" && cd REPO_DIR/docker/grafana/provisioning/alerting && install -m 644 contact-points.yml update-alert-rules-unifi.yml update-alert-rules-pfsense.yml heartbeat-alert-rule.yml notification-failure-alert-rule.yml "$HOME/bin/alerting/"'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/grafana-deploy.py'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/grafana-deploy.py --apply'
```

The second command is a dry run (the default) and changes nothing. `--apply`
backs up each file it replaces as `NAME.bak-<UTC timestamp>`, replaces the files
one at a time and prints a `manifest:` line for each. It is not atomic: if it
stops on an error it lists the files already replaced and the backup for each
(`cp -p BACKUP FILE` restores one). Details: `docs/live-deploy-runbook.md`,
section 5.

The compose lines stay manual and go to the grafana service only: the
`DISCORD_FAILURE_WEBHOOK_URL` line of 4b is still needed. If your
compose file does not already list `GRAFANA_WEBHOOK_SECRET` in the grafana service
environment, follow `docs/live-deploy-runbook.md`, section 5, step 4: it makes the
compose backup mode 600 and no-clobber (`umask 077`, `cp --no-clobber`), shows the
item `      - GRAFANA_WEBHOOK_SECRET` to add by hand after the `GF_SERVER_ROOT_URL`
line, and gives an `awk` check that only `grafana:` mentions the variable (the
value stays in Doppler; never run `docker compose config` for the check, it
prints resolved values). Then restart, as in 4d:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd /opt/siem && "$HOME/bin/siem-net-run" --require DISCORD_FAILURE_WEBHOOK_URL,GRAFANA_WEBHOOK_SECRET --optional BIND_ADDR,GF_SMTP_ENABLED,GF_SMTP_FROM_ADDRESS,GF_SMTP_HOST,GF_SMTP_PASSWORD,GF_SMTP_STARTTLS_POLICY,GF_SMTP_USER,GRAFANA_ADMIN_PASS,GRAFANA_ADMIN_USER,GRAFANA_INFLUX_PASSWORD,GRAFANA_INFLUX_USER,GRAFANA_PORT,GRAFANA_VERSION,OPENSEARCH_READONLY_PASSWORD,P1_EMAIL_TO,PROMETHEUS_GRAFANA_PASSWORD,PROMETHEUS_OTLP_GRAFANA_PASSWORD,SIEM_HOST,WAZUH_GRAFANA_RO_PASSWORD,WAZUH_GRAFANA_RO_USER -- docker compose up -d --no-deps grafana; echo "exit code: $?"'
```

Check: `docker compose ls` lists the project as running, the grafana container shows
`Up` (and `healthy` if it defines a healthcheck), and the checks of 4d pass.
Rollback: restore the compose backup `docker-compose.yml.bak-<UTC timestamp>`
and each replaced file from its `.bak-` copy, then run the restart above.

## Step 5. P1 email contact point (LIVE)

Request item 6. Source: `docs/channel-redundancy.md` (sections "Enable it",
"Provider-neutral checklist", "Example: Mailgun", "Rollback"); files
`email-contact-point.yml.example`, `email-notification-policy.yml.example`,
`.env.example`.

What it does: a P1 (`severity=critical` and `phone=true`) is also emailed by
Grafana itself, without n8n, Discord or Pushover. It is a double page by design
(VERIFIED).

Prerequisites (VERIFIED: the provider-neutral checklist):

- An SMTP provider account (Mailgun is the planned one) with a sending domain
  verified through the provider's DNS records, separate from any primary
  domain.
- An SMTP login for that domain, a From address on the verified domain, and the
  recipient address or addresses for `P1_EMAIL_TO`.
- Step 4 is finished and checked (one Grafana restart at a time).
- Step 0b done.

Mailgun values (VERIFIED against the page cited in `docs/channel-redundancy.md`,
read 2026-11-19 by that doc): host `smtp.mailgun.org`, port 587, STARTTLS.
INFERRED and to be checked at the provider for your account: the SMTP username
format, and a different host if the account is in another region. Use a
verified domain, not the sandbox (sandbox sends only to authorized recipients).

### 5a. Store the seven values in Doppler dev

In a terminal where Doppler is logged in. The non-secret values:

```
printf '%s' 'true' | doppler secrets set GF_SMTP_ENABLED --project homelab --config dev_network --silent > /dev/null
printf '%s' 'smtp.mailgun.org:587' | doppler secrets set GF_SMTP_HOST --project homelab --config dev_network --silent > /dev/null
printf '%s' 'MandatoryStartTLS' | doppler secrets set GF_SMTP_STARTTLS_POLICY --project homelab --config dev_network --silent > /dev/null
printf '%s' 'alerts@example.com' | doppler secrets set GF_SMTP_FROM_ADDRESS --project homelab --config dev_network --silent > /dev/null
printf '%s' 'oncall@example.com' | doppler secrets set P1_EMAIL_TO --project homelab --config dev_network --silent > /dev/null
```

Replace `alerts@example.com` and `oncall@example.com` with your own addresses (the
sender must be on the verified domain). The login and password, read without
echo:

```
read -rs -p "SMTP user: " VAL; echo
printf '%s' "$VAL" | doppler secrets set GF_SMTP_USER --project homelab --config dev_network --silent > /dev/null
read -rs -p "SMTP password: " VAL; echo
printf '%s' "$VAL" | doppler secrets set GF_SMTP_PASSWORD --project homelab --config dev_network --silent > /dev/null
unset VAL
```

Every command ends in `> /dev/null`. Variable names are VERIFIED
(`docs/channel-redundancy.md`, Settings); the `GF_SMTP_*` names themselves are
INFERRED from Grafana's `GF_<SECTION>_<KEY>` rule (stated in that doc's
"Verified" section).

### 5b. Pass the seven variables to Grafana (compose)

Same pattern as 4b, seven lines. The compose file does not carry them (VERIFIED:
the doc says "the repo does not do this for you"). In a session:

```
cd /opt/siem && B="docker-compose.yml.bak-$(date -u +%Y%m%dT%H%M%SZ)-email" && [ ! -e "$B" ] && ( umask 077 && cp docker-compose.yml "$B" ) && cmp docker-compose.yml "$B" && [ "$(stat -c %a "$B")" = 600 ] && echo "backup $B ok" && ! grep -q 'GF_SMTP_' docker-compose.yml && for V in GF_SMTP_ENABLED GF_SMTP_HOST GF_SMTP_USER GF_SMTP_PASSWORD GF_SMTP_FROM_ADDRESS GF_SMTP_STARTTLS_POLICY P1_EMAIL_TO; do sed -i "/- GRAFANA_WEBHOOK_SECRET=/a\\      - ${V}=\${${V}:-}" docker-compose.yml; done && grep -n -E 'GF_SMTP_|P1_EMAIL_TO' docker-compose.yml
```

As in 4b, the edit is gated on a fresh, verified, mode 600 backup of this run and
on the variables not being present already. The last command lists seven lines.
Empty defaults (`:-`) keep Compose from refusing to start when a value is unset.

### 5c. Copy the contact point

```
sudo install -m 644 REPO_DIR/docker/grafana/provisioning/alerting/email-contact-point.yml.example /opt/siem/grafana/provisioning/alerting/email-contact-point.yml
```

### 5d. Restart Grafana and check

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd /opt/siem && "$HOME/bin/siem-net-run" --require DISCORD_FAILURE_WEBHOOK_URL,GF_SMTP_ENABLED,GF_SMTP_FROM_ADDRESS,GF_SMTP_HOST,GF_SMTP_PASSWORD,GF_SMTP_STARTTLS_POLICY,GF_SMTP_USER,GRAFANA_WEBHOOK_SECRET,P1_EMAIL_TO --optional BIND_ADDR,GRAFANA_ADMIN_PASS,GRAFANA_ADMIN_USER,GRAFANA_INFLUX_PASSWORD,GRAFANA_INFLUX_USER,GRAFANA_PORT,GRAFANA_VERSION,OPENSEARCH_READONLY_PASSWORD,PROMETHEUS_GRAFANA_PASSWORD,PROMETHEUS_OTLP_GRAFANA_PASSWORD,SIEM_HOST,WAZUH_GRAFANA_RO_PASSWORD,WAZUH_GRAFANA_RO_USER -- docker compose up -d --no-deps grafana; echo "exit code: $?"'
```

Check `docker logs --since 5m grafana 2>&1 | tail -40` for SMTP or provisioning
errors, and that the contact point `email-p1` appears in Alerting.

### 5e. Merge the `email-p1` route as the FIRST route

In Alerting, Notification policies (the tree is one per organization; do not
load the `.example` file, VERIFIED). Add a child route as the first one, with
(VERIFIED from the example file): contact point `email-p1`, matchers
`severity = critical` and `phone = true`, group by `alertname`, group wait 30s,
group interval 5m, repeat interval 1h, and Continue matching subsequent sibling
nodes turned on (`continue: true`), so the n8n path still receives the P1.

### 5f. Test

1. Use the test action of the `email-p1` contact point in Grafana and confirm the
   mail arrives (the "test button" is INFERRED to exist in your version; the doc
   lists it as unverified).
2. End to end: a P1 that goes through the policy. The docs do not say how to
   produce one on demand (OPEN QUESTION, Q10). INFERRED approach: a temporary
   Grafana alert rule that always fires, labeled `severity=critical` and
   `phone=true`, deleted afterwards. Do this before step 8 enables Pushover,
   because such a label would also page the phone through n8n once Pushover is
   on. Confirm: the email arrives, Discord receives the router's message, and
   the heartbeat keeps arriving (it carries `phone=false`, so it never matches
   the email route; VERIFIED).

Rollback (VERIFIED: `docs/channel-redundancy.md`): remove the `email-p1` route,
remove `email-contact-point.yml` from the live folder, restore the compose
backup, restart Grafana. To stop mail without touching provisioning, set
`GF_SMTP_ENABLED` to `false` in Doppler dev and restart Grafana.

## Step 6. Expiry watch: config, secrets, dry run, schedule (LIVE)

Request item 5. Source: `docs/expiry-watch.md` ("Quick start", "Config
reference", "Channels and routing", "Scheduling") and
`docs/expiry-watch.example.toml`.

What it does: reads items that expire (a registry file, TLS certificates,
Grafana service account tokens, secret manager service tokens) and posts notices
to the n8n router, and directly to Matrix and email if routed there. It is
read-only toward the things it watches (VERIFIED).

Prerequisites:

- Python 3.11 or newer on LOGGING_BOX (VERIFIED: "You need Python 3.11 or
  newer").
- The router is live and healthy (step 1). Owner decision: the watch runs ON
  LOGGING_BOX and posts to n8n through a localhost port, because the watch
  requires an https router URL and allows plain http only for localhost
  (VERIFIED: `docs/expiry-watch.md`, config reference), so no plaintext path
  crosses the network. Section 6.0 sets that up.
- For email delivery from the watch itself: SMTP login values (step 5 provider).
- For the two token providers: throwaway read-only tokens to test with. The
  secret manager list permission is undocumented by the vendor; test with a
  throwaway token before relying on it (VERIFIED: "doppler_tokens"). The Grafana
  token needs `serviceaccounts:read` on scope `serviceaccounts:id:*` (VERIFIED).
  Start with only the registry and TLS providers; add the token providers in a
  second pass.
- The router side is done in section 6.1: the watch has its own endpoint and its
  own secret on the router, separate from Grafana's (VERIFIED: `docs/expiry-watch.md`,
  "The router credential"). It needs the merged router workflow imported live
  first, which 6.1 does.

### 6.0 A localhost URL for n8n (on LOGGING_BOX)

n8n is on the siem network and a macvlan network, and the docs reach it by the
name `n8n` from other containers (VERIFIED: `docs/live-deploy-runbook.md`,
section 4; `docs/examples/n8n-compose.example.yml`). A macvlan container cannot
be reached from its own host (VERIFIED: same section), so the watch needs a
port published on the host's loopback address.

Check first whether one is already published (read only):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker port n8n'
```

Expected if one exists: a line such as `PORT/tcp -> 127.0.0.1:HOST_PORT`. Empty
output means no port is published. A mapping to `0.0.0.0` is not acceptable
here, because it would expose the router webhook on every host address; handle it
as "not published on 127.0.0.1 only" and fix it in the same edit below.

If none is published on 127.0.0.1, publish one. n8n is deployed from its own
compose file, separate from this repo's `docker/docker-compose.yml` (VERIFIED:
header of `docs/examples/n8n-compose.example.yml`). Do not guess the internal
port: read it from that compose file (its `N8N_PORT` setting, or the port the
docs use). The docs reach n8n at `http://n8n/webhook/...`, which is port 80
(VERIFIED: runbook section 4 and `scripts/n8n_address.py`, default 80), not
n8n's own upstream default, so do not assume 5678. Find and note it:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo grep -n -i -E "N8N_PORT|ports:|container_name: n8n" N8N_COMPOSE_FILE'
```

`N8N_COMPOSE_FILE` is the compose file that defines n8n (`/opt/n8n/docker-compose.yml`
live, root owned, so `sudo` is used for every touch of it, as step 6.2 did). Back it
up first (`cp -p` keeps its mode, and the file may hold values), then edit it with
`sudoedit` to add this under the `n8n` service, with
`CONTAINER_PORT` the value you read and `HOST_PORT` any free port above 1024
that you choose (INFERRED: the `127.0.0.1:HOST:CONTAINER` form is standard
Compose syntax, not in a repo doc, and publishing on a container attached to
a bridge network is assumed to work alongside the macvlan one):

The edit is gated in the same `&&` chain on a backup made by this run: the name must
not exist yet, the copy must match the live file byte for byte, and only then does
`sudoedit` open the file:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'B="N8N_COMPOSE_FILE.bak-$(date -u +%Y%m%dT%H%M%SZ)" && sudo test ! -e "$B" && sudo cp -p N8N_COMPOSE_FILE "$B" && sudo cmp N8N_COMPOSE_FILE "$B" && echo "backup $B ok" && sudoedit N8N_COMPOSE_FILE'
```

```
    ports:
      - "127.0.0.1:HOST_PORT:CONTAINER_PORT"
```

Apply it by recreating only n8n, then immediately re-check the siem network,
because a recreate can drop it (VERIFIED: runbook, "Keep n8n on the siem
network").

SAFE N8N RECREATE. This is the only n8n recreate command in this runbook: 6.0, 6.1
and 6.2 and every rollback below use it. A plain `sudo docker compose up -d n8n`
writes empty values for any variable the compose file takes from the environment
(the heartbeat URL, and after 6.1 the expiry secret), and the outage would only show
afterwards (INFERRED hazard; the values reach compose through the `dev_network`
wrapper of step 0b.5, owner decision 2026-11-20, resolved). So the form below (1) records which variables the RUNNING
container holds, names only; (2) refuses to recreate unless every required variable
is non-empty in the compose command's own environment, before anything is touched;
(3) checks the new container and prints the exact recovery when a value is blank.
`HEARTBEAT_PING_URL` (and `HEARTBEAT_KIND`) must exist in `dev_network`: copy them
from where they live today the way step 0b item 2 copies a secret, with the item 3
check, before the first recreate. The function below takes the required variable
names and the preserve list as its two arguments, so there are two complete calls
and nothing to rewrite by hand: the first (BEFORE 6.1 item 1 has created
`EXPIRY_WATCH_ROUTER_TOKEN`) requires only the heartbeat variables, the second (from
6.1 item 2 on) also requires the expiry token. It uses the session variables set at
the top of this runbook (`owner_chk_vars` must have printed `variables ok`), quotes every
expansion, and its exit status is the real status: `recreate exit code: N` is the
last line it prints and it returns that N. In a session on LOGGING_BOX, define it:

```
unset -f owner_recreate_n8n 2> /dev/null
owner_recreate_n8n() {
  : "runbook-block-recreate-v4"
  local R
  owner_chk_vars || return 1
  if ! docker exec n8n true > /dev/null 2>&1; then echo "STOP: no running container named n8n; nothing recorded and nothing recreated"; echo "recreate exit code: 1"; return 1; fi
  if ! ( umask 077 && docker exec n8n sh -c 'for V in HEARTBEAT_PING_URL HEARTBEAT_KIND EXPIRY_WATCH_ROUTER_SECRET; do if [ -n "$(printenv $V)" ]; then echo "$V set"; else echo "$V unset"; fi; done' > "$HOME/n8n-env-before.txt" ); then echo "STOP: could not read the running container; nothing recreated"; echo "recreate exit code: 1"; return 1; fi
  cat "$HOME/n8n-env-before.txt"
  ( cd "$N8N_COMPOSE_DIR" && REQ_VARS="$1" PRESERVE="$2" "$HOME/bin/siem-net-run" --require "$2" -- sh -c 'for V in $REQ_VARS; do if [ -z "$(printenv $V)" ]; then echo "REFUSING: $V is empty in the compose environment; n8n was NOT recreated"; exit 1; fi; done; sudo --preserve-env="$PRESERVE" docker compose up -d n8n' )
  R=$?
  if [ $R -eq 0 ]; then docker port n8n && docker network inspect "$SIEM_NETWORK" --format "{{range .Containers}}{{.Name}} {{end}}" && docker exec n8n sh -c 'test -n "$(printenv HEARTBEAT_PING_URL)"'; R=$?; fi
  if [ $R -eq 0 ]; then echo "n8n recreated, heartbeat variable set"; else echo "RECOVERY: the recreate failed or HEARTBEAT_PING_URL is blank in the new container. n8n data is on its volume and is unaffected. Put the value in dev_network (step 0b item 2 form), run the recreate call again, then the step 1 presence check. Until then the heartbeat is off and the observer alerts after about 20 minutes."; fi
  echo "recreate exit code: $R"
  return $R
}
OWNER_SUM_RECREATE="$(declare -f owner_recreate_n8n | sha256sum | cut -d' ' -f1)"
```

Then call it. Each call first checks two things (the same gate guards every function
block in this runbook). `OWNER_FRESH=1`, set when the session variables were pasted,
means none of the function names existed before the paste (an older read-only or
inherited function cannot be removed, so it would be reported there as `STALE
FUNCTION`). And the sha256 of the installed definition equals the one taken right
after it was pasted, so it was not replaced or edited in between. This does NOT prove
the pasted text matches the runbook character for character (a mistyped paste hashes
to its own value); to check that, run `echo "$OWNER_SUM_RECREATE"` and compare it with
the same value on a second shell you pasted the block into. Before 6.1
item 1 (heartbeat variables only):

```
if [ "$OWNER_FRESH" = 1 ] && [ "$(declare -f owner_recreate_n8n | sha256sum | cut -d' ' -f1)" = "$OWNER_SUM_RECREATE" ]; then owner_recreate_n8n "HEARTBEAT_PING_URL HEARTBEAT_KIND" "HEARTBEAT_PING_URL,HEARTBEAT_KIND"; else echo "STALE FUNCTION: open a fresh bash shell, set the session variables and paste again"; false; fi
```

From 6.1 item 2 on (heartbeat variables and the expiry token):

```
if [ "$OWNER_FRESH" = 1 ] && [ "$(declare -f owner_recreate_n8n | sha256sum | cut -d' ' -f1)" = "$OWNER_SUM_RECREATE" ]; then owner_recreate_n8n "HEARTBEAT_PING_URL HEARTBEAT_KIND EXPIRY_WATCH_ROUTER_TOKEN" "HEARTBEAT_PING_URL,HEARTBEAT_KIND,EXPIRY_WATCH_ROUTER_TOKEN"; else echo "STALE FUNCTION: open a fresh bash shell, set the session variables and paste again"; false; fi
```

Check the status the call returned with `echo $?`: only `0` is success. If the running
container is absent the function stops before recording anything or recreating.

Compare the `$HOME/n8n-env-before.txt` lines with the step 1 presence check after
the recreate: every variable that said `set` before must say `set` after. Delete the
file when done (it holds names only). `--preserve-env=LIST` needs a sudoers rule that
allows it and refuses with a clear message if not (INFERRED); then the refusal
leaves the old container running and nothing is lost. Expect the new
`127.0.0.1:HOST_PORT` line and `n8n` in the container list. Then send the
baseline test alert and confirm the next heartbeat ping arrives within 6 minutes
(step 1):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-test-router.py; echo "exit code: $?"'
```

Expected: six lines ending `PASS` and `failed cases: 0` (VERIFIED: runbook section
4); it posts three visible test messages to Discord. A recreate restarts n8n,
so do this in a quiet moment; the heartbeat and any firing alert wait for the
restart.

Prove the loopback port reaches the Grafana router without sending an alert, with a
request that carries no secret and expects a 401 or 403 (VERIFIED: runbook section
4, cases 1 to 3). The private path is read on the box, so it never lands in your
terminal or in the command text. This URL is for the probe only; the expiry watch
uses its own path (6.1):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'P=$(cat "$HOME/.config/doppler-siem/router-path") && curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Content-Type: application/json" -d "{}" "http://127.0.0.1:HOST_PORT/webhook/$P"'
```

A `401` or `403` means the localhost URL reaches the authenticated router. A
`404` means the path or port is wrong; `Connection refused` means no port is
published. (`PRIVATE_WEBHOOK_PATH` in the placeholder table is the content of
that `router-path` file.)

Rollback: restore `N8N_COMPOSE_FILE.bak-<UTC timestamp>` over the compose file with
`sudo cp -p`, run the
SAFE N8N RECREATE above (never a plain `docker compose up`), and re-check the siem
network and the heartbeat. Nothing
else changes; the siem network name `n8n` still serves Grafana.

### 6.0a Rehearse the router export and import on a scratch n8n (on LOGGING_BOX)

DECIDED 2026-11-20 (owner: "Rehearse on a scratch n8n first"): do this BEFORE the live
router import in 6.1 item 3. Nothing here has been run yet; every statement about how
n8n 2.10.3 behaves below is VERIFIED only where a URL and date are given, and
INFERRED otherwise.

Target: a throwaway n8n container on `LOGGING_BOX`, started from the same image as the
live `n8n` container, plus the live n8n's own CLI for one read-only export.

Change: the function below (1) refuses if the scratch folder or container name
is already in use; (2) reads the live image id with `docker inspect` and the live
router with `n8n export:workflow --id=ROUTER_ID` into a mode 600 file in a new scratch
folder (mode 700); (3) starts the scratch container with a different, random encryption key, no
other environment and no credentials, with NO network (`--network none`) and NO
published port: every step runs through `docker exec` and the CLI inside it, so the
editor and API are never reachable by any local user; (4) imports the
file there with `n8n import:workflow`; (5) compares the node count and the list of
credential references (type and name only, never a value) between the live export and
the scratch export; (6) tears the container and the folder down on every path, then
reads both back. It publishes nothing on the live n8n and changes nothing on it.

Evidence you get:

- VERIFIED (https://docs.n8n.io/hosting/cli-commands/, read 2026-11-20): the CLI has
  `export:workflow` with `--id` and `--output`, `import:workflow` with `--input`, and
  `publish:workflow --id`; an imported workflow is deactivated by default
  (`--activeState` defaults to `false`); n8n exports ids along with the workflow, and
  an import overwrites a workflow or credential that has the same id.
- VERIFIED (https://docs.n8n.io/hosting/installation/docker/, read 2026-11-20): the
  data folder in the image is `/home/node/.n8n`, the default port is 5678, and the
  `N8N_ENCRYPTION_KEY` variable can be set instead of keeping a key in that folder.
  That page is marked outdated by n8n.
- NOT in those docs, so INFERRED: the file format of an export (array or one object),
  what an import does with a credential id that does not exist in the target, and the
  exact output of `list:workflow`. The rehearsal prints what actually happens.

What to expect about credentials. A workflow export does not carry credentials, only
references: each node that uses one holds the credential type, its id and its name.
The scratch n8n has none of them. INFERRED: the import still succeeds and the node
keeps its dangling reference (type, id, name), and the n8n interface would show it as
a missing credential on that node. If the import FAILS on a missing credential, that
is a finding: stop, do not start the live import, and keep the step 2 archive as the
only proven restore. The comparison below treats a changed reference list as a failure.

How the scratch container cannot reach the real Discord, Pushover or Healthchecks. It
gets no credential and no environment variable of the live n8n: its only environment is
a mode 600 file holding a fresh random `N8N_ENCRYPTION_KEY` (never the live key, which
the function never reads) and `HOME`. The router reads its Discord, Pushover and
Healthchecks addresses from environment variables of the live container
(`HEARTBEAT_PING_URL` and the others in 6.1), which do not exist here, and the
imported workflow is inactive and is never executed. The container shares no folder,
volume or Docker network name with `/opt/n8n` or the live data volume: its only two
mounts are folders under the new scratch folder. Because the container runs with
`--network none`, it has no network interface beyond loopback inside itself, so n8n's own
telemetry, version check and template fetches cannot reach any host (this follows from
Docker's `none` network, INFERRED for n8n 2.10.3; a failed call is expected to be
silent). As defense in depth the env file also sets `N8N_DIAGNOSTICS_ENABLED=false`,
`N8N_VERSION_NOTIFICATIONS_ENABLED=false` and `N8N_TEMPLATES_ENABLED=false` (names and
defaults VERIFIED at
https://docs.n8n.io/deploy/host-n8n/configure-n8n/basic-configuration/use-environment-variables/deployment.md,
read 2026-11-20; that they take effect in 2.10.3 is INFERRED). There is no published
port, so nobody else on the box can reach the fresh, unowned n8n editor.

How the export is copied out. `docker cp` copies a symlink as a symlink, so a link
inside the live folder, or a link already at the host destination, could pull another
file out or write through it. The function therefore (1) refuses unless the exported
file in the live container is a regular file and not a symlink (`test -f` and `! test
-L` through `docker exec`); (2) copies into a brand new directory made with `mktemp -d`
under umask 077 inside the mode 700 scratch folder, never to a predictable name; (3)
before it parses anything, refuses unless the copy is a regular file, not a symlink,
owned by you with a link count of 1, and between 1 byte and 5 MB; (4) only then installs
it as mode 600 `live.json` and parses that copy. That `docker cp` makes the host file
owned by the user who runs it is INFERRED; if your Docker makes it another owner, the
check stops the rehearsal with a message and nothing is parsed.

Resource limits, so a runaway scratch n8n cannot starve the live stack: `--memory 2g
--memory-swap 2g` (the same value for swap means no swap), `--cpus 1`, `--pids-limit 256`, `--security-opt no-new-privileges`,
`--cap-drop ALL` and `--restart no`. A read-only root file system (`--read-only` with
tmpfs mounts) is NOT used: whether n8n 2.10.3 starts that way is unverified, so it is
left out rather than guessed.

Why 2 GB and not 1 GB. The first live run (2026-11-20) used 1 GB and printed `variables
ok`, then `REHEARSAL FAILED at: the import (exit 137)`, then `teardown ok` and
`rehearsal exit code: 137`. Exit 137 is a SIGKILL. The most likely cause (INFERRED, not
measured: the container's `OOMKilled` flag was not read in that run) is the 1 GB limit
killing the n8n command line import, which boots the whole application and a fresh
database. The old message blamed the export format; that was wrong, and 137 says nothing
about the format. Read-only checks afterward (VERIFIED 2026-11-20 by the owner's box
read): no leftover container, folder or live temporary folder; the box has 64 GiB of
RAM with 30 GiB available; the live n8n container uses about 280 MiB of its 2 GiB
limit. So the scratch limit now matches the live container's 2 GiB. Whether 2 GB is
enough is not yet shown: the rehearsal has not passed. The function now reads
`docker inspect --format '{{.State.OOMKilled}}'` of the scratch container before
teardown when the import fails, and reports two cases separately: exit 137 or
`OOMKilled=true` prints `the process was killed ... the memory limit is the likely
cause, NOT evidence about the export format`; any other nonzero exit keeps the message
that the format is not accepted. If you see the killed message again at 2 GB, stop and
report it; do not raise the limit on your own.

Blast radius: one extra container (at most 2 GB and one CPU) and one folder under your
home for a few minutes; the live n8n gets one `docker exec` export into a new, random,
mode 700 folder under its `/tmp`, removed as soon as the file is copied out (and
reported loudly, with a nonzero status, if it cannot be removed).

Interruption. The function sets a trap on INT, TERM and HUP (and EXIT) that runs the
same idempotent teardown, then returns 130 and prints `REHEARSAL INTERRUPTED`. The
trap replaces any trap of your own on those signals for the length of the run and is
cleared when the function returns. It cannot run if the terminal or the machine dies
without delivering a signal (a `kill -9`, a power loss). What remains then: a container
named `n8n-rehearsal` and the folder `$HOME/n8n-rehearsal`, which holds the workflow
export (it contains the router's private path; mode 700 folder, mode 600 file), the
throwaway key file and the scratch database, plus possibly a folder
`/tmp/router-rehearsal.` followed by six random characters inside the live `n8n`
container (made with `mktemp -d`, so it is new, mode 700 and never an existing or
symlinked path; the old fixed name `/tmp/router-rehearsal.json` is never used). If the
function itself cannot remove that folder it prints `LIVE LEFTOVER` with the exact path
and the command, and returns nonzero even when the rehearsal passed. Find and remove
everything, then read back:

```
docker ps -a --filter name=n8n-rehearsal --format '{{.Names}} {{.Status}}'
ls -ld "$HOME/n8n-rehearsal"
docker rm -f n8n-rehearsal
[ -d "$HOME/n8n-rehearsal" ] && [ ! -L "$HOME/n8n-rehearsal" ] && rm -rf -- "$HOME/n8n-rehearsal"
docker exec n8n sh -c 'ls -d /tmp/router-rehearsal.??????'
docker exec n8n sh -c 'rm -rf -- /tmp/router-rehearsal.??????'
docker exec n8n sh -c 'ls -d /tmp/router-rehearsal.??????'
docker ps -a --filter name=n8n-rehearsal -q | wc -l
ls -ld "$HOME/n8n-rehearsal"
```

The two `ls -d` lines before the removal show what is there; the one after it must
print `No such file or directory`, the next line `0`, and the last
`No such file or directory`. Do the removal only
when no rehearsal is running in another shell.

Rollback: the function tears down on every path it can control (see above). Nothing on
the live side needs undoing except the leftover temporary folder named above.

In a session on LOGGING_BOX with the session variables set (`owner_chk_vars` printed
`variables ok`, `OWNER_FRESH` is `1`):

```
unset -f owner_rehearse_down owner_rehearse_router 2> /dev/null
owner_rehearse_down() {
  : "runbook-block-rehearse-down-v3"
  local N="$1" D="$2" C="$3" M="$4" L="$5" S=0
  if [ -n "$L" ]; then docker exec n8n rm -rf -- "$L" > /dev/null 2>&1 || { echo "LIVE LEFTOVER: $L is still inside the live n8n container (it holds the router export); remove it with: docker exec n8n rm -rf -- $L"; S=1; }; fi
  if [ "$C" = 1 ]; then docker rm -f "$N" > /dev/null 2>&1 || { echo "TEARDOWN FAILED: run docker rm -f $N"; S=1; }; fi
  if [ "$M" = 1 ] && [ ! -L "$D" ]; then rm -rf -- "$D" || { echo "TEARDOWN FAILED: remove $D by hand"; S=1; }; fi
  return $S
}
owner_rehearse_router() {
  : "runbook-block-rehearse-v4"
  local SCRATCH_NAME=n8n-rehearsal SCRATCH_DIR="$HOME/n8n-rehearsal"
  local IMG R=0 INTR=0 TDFAIL=0 LD="" H="" F SZ K I MADE_DIR=0 MADE_CTR=0 OOM LIVE_NODES SC_NODES LIVE_CREDS SC_CREDS COUNT_PY CRED_PY
  COUNT_PY='import json,sys; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; print(len(d["nodes"]))'
  CRED_PY='import json,sys; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; print("\n".join(sorted({"%s:%s" % (t, (c or {}).get("name", "")) for n in d["nodes"] for t, c in (n.get("credentials") or {}).items()})))'
  owner_chk_vars || return 1
  [[ "$SCRATCH_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] || { echo "REHEARSAL STOP: the scratch folder path has unsafe characters"; echo "rehearsal exit code: 1"; return 1; }
  if [ -e "$SCRATCH_DIR" ] || [ -L "$SCRATCH_DIR" ]; then echo "REHEARSAL STOP: $SCRATCH_DIR already exists (an earlier run?); check it and remove it by hand; nothing was touched"; echo "rehearsal exit code: 1"; return 1; fi
  if [ -n "$(docker ps -a --filter "name=^${SCRATCH_NAME}\$" -q)" ]; then echo "REHEARSAL STOP: a container named $SCRATCH_NAME already exists; nothing was touched"; echo "rehearsal exit code: 1"; return 1; fi
  IMG="$(docker inspect --format '{{.Image}}' n8n)"
  [[ "$IMG" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "REHEARSAL STOP: the live image id could not be read (got '${IMG}'); nothing was touched"; echo "rehearsal exit code: 1"; return 1; }
  trap 'if owner_rehearse_down "$SCRATCH_NAME" "$SCRATCH_DIR" "$MADE_CTR" "$MADE_DIR" "$LD"; then LD=""; echo "REHEARSAL INTERRUPTED: scratch container, folder and live export removed"; else TDFAIL=1; echo "REHEARSAL INTERRUPTED: teardown INCOMPLETE, see the messages above"; fi; INTR=1; MADE_CTR=0; MADE_DIR=0' INT TERM HUP
  trap 'owner_rehearse_down "$SCRATCH_NAME" "$SCRATCH_DIR" "$MADE_CTR" "$MADE_DIR" "$LD"' EXIT
  ( umask 077; mkdir -m 700 "$SCRATCH_DIR" ) || { trap - INT TERM HUP EXIT; echo "REHEARSAL STOP: cannot create the scratch folder; nothing was touched"; echo "rehearsal exit code: 1"; return 1; }
  MADE_DIR=1
  ( umask 077; mkdir -m 700 "$SCRATCH_DIR/data" "$SCRATCH_DIR/work" ); R=$?; [ $R -eq 0 ] || echo "REHEARSAL FAILED at: scratch folders (exit $R)"
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then K="$(openssl rand -hex 32)"; R=$?; [[ "$K" =~ ^[0-9a-f]{64}$ ]] || R=1; if [ $R -eq 0 ]; then ( umask 077; printf 'HOME=/home/node\nN8N_ENCRYPTION_KEY=%s\nN8N_DIAGNOSTICS_ENABLED=false\nN8N_VERSION_NOTIFICATIONS_ENABLED=false\nN8N_TEMPLATES_ENABLED=false\n' "$K" > "$SCRATCH_DIR/env" ); R=$?; fi; K=""; [ $R -eq 0 ] && [ "$(stat -c %a "$SCRATCH_DIR/env")" = 600 ] && [ "$(wc -c < "$SCRATCH_DIR/env")" -ge 120 ]; R=$?; [ $R -eq 0 ] || echo "REHEARSAL FAILED at: the scratch key file (not written, not mode 600 or too short)"; fi
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then LD="$(docker exec n8n mktemp -d /tmp/router-rehearsal.XXXXXX)"; R=$?; [[ "$LD" =~ ^/tmp/router-rehearsal\.[A-Za-z0-9]{6}$ ]] || { R=1; LD=""; }; [ $R -eq 0 ] || echo "REHEARSAL FAILED at: making a new private folder inside the live container (mktemp -d is INFERRED to exist in the n8n image); nothing was exported"; fi
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then docker exec n8n n8n export:workflow --id="$ROUTER_ID" --output="$LD/router.json" > /dev/null && docker exec n8n sh -c 'test -f "$1" && ! test -L "$1"' sh "$LD/router.json" && H="$(umask 077; mktemp -d "$SCRATCH_DIR/work/in.XXXXXX")" && [[ "$H" =~ ^/[A-Za-z0-9._/-]+/work/in\.[A-Za-z0-9]{6}$ ]] && ( umask 077; docker cp "n8n:$LD/router.json" "$H/" ); R=$?; if docker exec n8n rm -rf -- "$LD" > /dev/null 2>&1; then LD=""; else echo "LIVE LEFTOVER: $LD is still inside the live n8n container (it holds the router export); remove it with: docker exec n8n rm -rf -- $LD"; TDFAIL=1; fi; [ $R -eq 0 ] || echo "REHEARSAL FAILED at: the read-only export of the live router (exit $R)"; fi
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then F="$H/router.json"; [ -f "$F" ] && [ ! -L "$F" ] && [ "$(stat -c '%u %h' "$F")" = "$(id -u) 1" ] && SZ="$(stat -c %s "$F")" && [ "$SZ" -gt 0 ] && [ "$SZ" -le 5242880 ] && install -m 600 "$F" "$SCRATCH_DIR/work/live.json" && LIVE_NODES="$(python3 -c "$COUNT_PY" < "$SCRATCH_DIR/work/live.json")" && LIVE_CREDS="$(python3 -c "$CRED_PY" < "$SCRATCH_DIR/work/live.json")"; R=$?; case "$LIVE_NODES" in ''|*[!0-9]*|0) R=1;; esac; [ $R -eq 0 ] || echo "REHEARSAL FAILED at: reading the live export (not a plain file owned by you with one link and 1 byte to 5 MB, or not a workflow with a positive node count, got '${LIVE_NODES}')"; fi
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then MADE_CTR=1; docker run -d --name "$SCRATCH_NAME" --network none --restart no --memory 2g --memory-swap 2g --cpus 1 --pids-limit 256 --security-opt no-new-privileges --cap-drop ALL --user "$(id -u):$(id -g)" --env-file "$SCRATCH_DIR/env" -v "$SCRATCH_DIR/data:/home/node/.n8n" -v "$SCRATCH_DIR/work:/work" "$IMG" > /dev/null; R=$?; [ $R -eq 0 ] || echo "REHEARSAL FAILED at: starting the scratch container (exit $R)"; fi
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then R=1; for I in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do if docker exec "$SCRATCH_NAME" n8n list:workflow > /dev/null 2>&1; then R=0; break; fi; sleep 3; done; [ $R -eq 0 ] || echo "REHEARSAL FAILED at: the scratch n8n did not answer within 60 seconds (docker logs $SCRATCH_NAME shows why)"; fi
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then docker exec "$SCRATCH_NAME" n8n import:workflow --input=/work/live.json; R=$?; if [ $R -ne 0 ]; then OOM="$(docker inspect --format '{{.State.OOMKilled}}' "$SCRATCH_NAME" 2> /dev/null)"; if [ $R -eq 137 ] || [ "$OOM" = true ]; then echo "REHEARSAL FAILED at: the import (exit $R): the process was killed (OOMKilled=${OOM:-unknown}): the memory limit is the likely cause, NOT evidence about the export format"; else echo "REHEARSAL FAILED at: the import (exit $R): the export format is NOT accepted by this n8n; do not rely on owner_router_rollback"; fi; fi; fi
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then [ "$(docker exec "$SCRATCH_NAME" n8n list:workflow | grep -c "^$ROUTER_ID")" = 1 ]; R=$?; [ $R -eq 0 ] || echo "REHEARSAL FAILED at: the imported router is not listed exactly once"; fi
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then docker exec "$SCRATCH_NAME" n8n export:workflow --id="$ROUTER_ID" --output=/work/scratch.json > /dev/null && SC_NODES="$(python3 -c "$COUNT_PY" < "$SCRATCH_DIR/work/scratch.json")" && SC_CREDS="$(python3 -c "$CRED_PY" < "$SCRATCH_DIR/work/scratch.json")"; R=$?; [ $R -eq 0 ] || echo "REHEARSAL FAILED at: exporting the imported copy"; fi
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then [ "$SC_NODES" = "$LIVE_NODES" ]; R=$?; [ $R -eq 0 ] || echo "REHEARSAL FAILED at: node count (live $LIVE_NODES, scratch '${SC_NODES}')"; fi
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then [ "$SC_CREDS" = "$LIVE_CREDS" ]; R=$?; [ $R -eq 0 ] || echo "REHEARSAL FAILED at: the credential references differ (live '${LIVE_CREDS}', scratch '${SC_CREDS}')"; fi
  if [ $R -eq 0 ] && [ "$INTR" = 0 ]; then echo "rehearsal compare ok: $LIVE_NODES nodes in both"; echo "credential references (type:name, names only):"; printf '%s\n' "$LIVE_CREDS"; fi
  owner_rehearse_down "$SCRATCH_NAME" "$SCRATCH_DIR" "$MADE_CTR" "$MADE_DIR" "$LD" || { R=1; TDFAIL=1; }
  [ "$TDFAIL" = 0 ] || R=1
  [ "$INTR" = 0 ] || R=130
  trap - INT TERM HUP EXIT
  if [ -e "$SCRATCH_DIR" ] || [ -n "$(docker ps -a --filter "name=^${SCRATCH_NAME}\$" -q)" ]; then echo "TEARDOWN INCOMPLETE: the scratch folder or container is still there"; R=1; else echo "teardown ok: scratch container and folder are gone"; fi
  echo "rehearsal exit code: $R"
  return $R
}
OWNER_SUM_REHEARSE="$(declare -f owner_rehearse_down owner_rehearse_router | sha256sum | cut -d' ' -f1)"
if [ "$OWNER_FRESH" = 1 ] && [ "$(declare -f owner_rehearse_down owner_rehearse_router | sha256sum | cut -d' ' -f1)" = "$OWNER_SUM_REHEARSE" ]; then owner_rehearse_router; else echo "STALE FUNCTION: a read-only or older owner_rehearse_router exists; open a fresh bash shell, set the session variables and paste again"; false; fi
```

`rehearsal exit code: 0` is the only success (the pasted block itself ends with the
function's status, so `$?` after the paste is that same number); it is preceded by
`teardown ok`. Record the node count and the credential
references it printed. A refusal prints `REHEARSAL STOP` and touches nothing. The
rehearsal does not publish: an imported workflow is inactive by default (VERIFIED, URL
above), and the function never calls `publish:workflow`.

What this rehearsal does NOT prove:

- The live webhook registration: the scratch n8n never serves the live private path,
  and the imported copy is inactive, so whether the live n8n registers, replaces or
  drops a webhook after the live import and publish is still unverified (6.1 item 4
  finds out).
- The Grafana path: the scratch n8n is not reachable from Grafana, and the saved
  `router-path` file is not read, so the contact point's address is not exercised.
- The real credentials: none exist in the scratch n8n, so it does not show that the
  live import keeps the live credentials attached, that Discord, Pushover or
  Healthchecks accept a call, or that a dangling reference behaves the same on the
  live n8n (INFERRED that it does).
- The repo router file: it rehearses the export of the CURRENT live router and its
  import, which is the round trip that `owner_router_rollback` needs. It does not
  import `n8n/grafana-alert-router.json` or run the import helper script.
- That the scratch key file and user mapping work for every image tag: the
  `--user` and `HOME` setup is INFERRED. A failure there stops the function and tears
  down, and it says nothing about the live n8n.

Until the owner has run it and seen `rehearsal exit code: 0`, the `owner_router_rollback`
export format stays INFERRED, not VERIFIED; after a pass it is VERIFIED only for the
export of this n8n version as read by the same version's import, on the date of the
run, and only for the node count and the credential references.

### 6.1 The router's own endpoint and secret (on LOGGING_BOX)

Source: `docs/expiry-watch.md`, "The router credential" and its owner steps;
`docs/update-alerting.md` (the expiry watch paragraph); `docs/live-deploy-runbook.md`
sections 3 and 4; `docs/heartbeat.md` (settings); the merged PR #128 text. Nothing
runs from the repo; each step here is a live change.

What exists (VERIFIED: `docs/expiry-watch.md`): the router has a second entry,
the `Expiry Watch Webhook` node, with its own private path. A `Check Expiry
Secret` node compares the `Authorization` header with `Bearer ` plus the n8n
container variable `EXPIRY_WATCH_ROUTER_SECRET`. Grafana's webhook and its
credential are untouched, and the Grafana secret is never used for the watch.
Rotating or revoking one never touches the other. The watch's side of the same
value is `EXPIRY_WATCH_ROUTER_TOKEN`.

Cost to know before you start (VERIFIED: `docs/expiry-watch.md`): the router
accepts only item names of letters, digits, space, dot, colon and hyphen,
starting with a letter or digit, up to 100 characters. An item name with an
underscore, slash, `@`, backtick, angle bracket, asterisk or any non-ASCII
character gets a uniform 403 and the watch fails loudly. Rename such items in the
registry or at their provider. Also, the notice text the router sends to Discord
and the phone is built by the router from `item`, `kind` and `stage`; owner,
dates and runbook links stay in the watch's own output and its Matrix and email
channels.

Prerequisites: step 0b (the `dev_network` config exists), section 6.0 (the
localhost port), the `dev_network` token and wrapper of step 0b.5 on LOGGING_BOX, and the
heartbeat healthy (step 1) so you can tell if the re-import disturbs the router.

**1. Generate the new secret and store it (watch side).** A new random value, not
the Grafana secret. It goes in on stdin, with `--silent` and `> /dev/null`, and is
never printed. The `openssl rand -base64 32` form (44 characters) is the one the
docs use (VERIFIED: `docs/update-alerting.md`, `docs/expiry-watch.md`). It prints a
trailing newline. The watch refuses a token that holds anything but printable
characters (VERIFIED: `scripts/expiry_watch.py`, the `_TOKEN` pattern allows 0x21 to
0x7e), and the router compares the value byte for byte, so a stored newline would
make every real run exit 2. Strip it, then read back only the length:

```
openssl rand -base64 32 | tr -d '\n' | doppler secrets set EXPIRY_WATCH_ROUTER_TOKEN --project homelab --config dev_network --silent > /dev/null
doppler secrets get EXPIRY_WATCH_ROUTER_TOKEN --plain --project homelab --config dev_network | wc -c
```

The second command prints a count, never the value. Expect `44`, or `45` if
`--plain` adds its own newline (NOT DOCUMENTED, see step 0b item 2). Any other
number: delete the secret in Doppler and redo this item. Do not also run the "Value
for EXPIRY_WATCH_ROUTER_TOKEN" prompt in 6b: this command is that step. The value
is now only in Doppler.

**2. Give the n8n container the same value as `EXPIRY_WATCH_ROUTER_SECRET`.** The
repo docs say: an environment entry in the n8n compose file with an empty
default, and `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` set there (VERIFIED:
`docs/expiry-watch.md` owner step 1; the heartbeat doc shows the same shape,
`- HEARTBEAT_PING_URL=${HEARTBEAT_PING_URL:-}`, and says the blocking setting is
needed). That setting is already required for the heartbeat (VERIFIED:
`docs/heartbeat.md`), so it should already be present; confirm it. Back up the
n8n compose file first (N8N_COMPOSE_FILE and N8N_COMPOSE_DIR as in 6.0), then add
this entry under the `n8n` service `environment:` list with `sudoedit`. The value
comes from the watch-side name; mapping `_TOKEN` to `_SECRET` in the entry is an
INFERRED choice that avoids storing the secret twice in Doppler (a second Doppler
key with the `_SECRET` name is the alternative):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'B="N8N_COMPOSE_FILE.bak-$(date -u +%Y%m%dT%H%M%SZ)-expiry" && sudo test ! -e "$B" && sudo cp -p N8N_COMPOSE_FILE "$B" && sudo cmp N8N_COMPOSE_FILE "$B" && echo "backup $B ok" && sudoedit N8N_COMPOSE_FILE'
```

(The edit opens only after the backup of this run exists and matches the live file.)

```
      - EXPIRY_WATCH_ROUTER_SECRET=${EXPIRY_WATCH_ROUTER_TOKEN:-}
      - N8N_BLOCK_ENV_ACCESS_IN_NODE=false
```

(Only add the second line if the file does not already carry it. Step 6.2 below
adds `N8N_PAYLOAD_SIZE_MAX=1` after that line, so do 6.2 in this same edit and one
recreate if you have not applied it yet: its `sed` needs the
`N8N_BLOCK_ENV_ACCESS_IN_NODE=false` line to exist.) Recreate n8n with the SAFE N8N
RECREATE of 6.0 using its SECOND call (the one that also requires
`EXPIRY_WATCH_ROUTER_TOKEN`; it refuses, before touching n8n, when the value is
empty), and read its `recreate exit code`; it re-checks the siem network itself.

RESOLVED (owner decision 2026-11-20): how n8n's variables reach `docker compose` on
EVERY recreate. The entries above take their values from the environment of the
compose command. A recreate run without them (a plain `sudo docker compose up -d
n8n`, as the 2026-11-20 run of 6.2 was) writes empty values: `HEARTBEAT_PING_URL`
and `HEARTBEAT_KIND` go blank (the heartbeat turns off, the observer reports down
after about 20 minutes) and `EXPIRY_WATCH_ROUTER_SECRET` goes blank (the watch gets
403). INFERRED, because no repo doc says how the heartbeat variables reach the
compose run today. The answer is that n8n's compose always runs through the
`dev_network` wrapper `siem-net-run` (step 0b.5), with the heartbeat values kept in
`dev_network` too, and no env file on disk. The SAFE N8N RECREATE block in 6.0 is
that form written out and is the form used everywhere below; it is INFERRED
(`sudo --preserve-env=LIST` needs the sudoers rule to allow it, and refuses with a
clear message if not). The wrapper's token is not in the preserve list, so
`sudo` drops it before `docker compose` runs.

Check presence only, never the value:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n sh -c "if [ -n \"\$EXPIRY_WATCH_ROUTER_SECRET\" ]; then echo EXPIRY_WATCH_ROUTER_SECRET set; else echo EXPIRY_WATCH_ROUTER_SECRET unset; fi; echo N8N_BLOCK_ENV_ACCESS_IN_NODE=\${N8N_BLOCK_ENV_ACCESS_IN_NODE:-unset}"'
```

Expect `set` and `false`. While env access is blocked or the variable is empty,
the watch gets 403 and exits 1 (VERIFIED: `docs/expiry-watch.md`); Grafana is
unaffected.

**3. Re-import the router with the live import helper.** Use the existing router
and handler ids, so the import overwrites the router in place (VERIFIED:
`docs/live-deploy-runbook.md` section 3), and run it with the Doppler token the
helper already uses. Order, from the helper's own docstring: the error handler is
imported FIRST and its id passed to the router import, so the router's
`errorWorkflow` setting points at a real workflow. The live handler already exists
(`HANDLER_ID`), so only the router is re-imported here, with `--error-workflow-id
HANDLER_ID`. On a fresh box, import the handler first (`docs/live-deploy-runbook.md`,
section 3). Do not leave `--error-workflow-id` out: the router would then lose its
error workflow setting.

The import is an in-place overwrite of the live, active router, and the helper
always writes the workflow INACTIVE (`active` is set to false in the script, and the
live deploy runbook says "Both workflows import inactive"). So from the moment the
import finishes until the publish and the n8n restart below have finished, the
router receives nothing. That is the alert gap: Grafana's webhook calls fail (404
or a refused connection), the heartbeat pings stop, and a real alert that fires
inside the gap is delayed until Grafana retries or repeats it (INFERRED; the repeat
interval is up to 4 hours for warnings). The gap is the restart time, about a minute.
Keep it short: run import, publish and restart as ONE sequence in a quiet moment,
right after a heartbeat ping arrived (step 1), and not while any game-day or test
scenario runs. The observer tolerates about 20 minutes of silence, so one or two
missed pings do not alert. MAXIMUM GAP: if the router is not active again 5
minutes after the import started, stop troubleshooting and run the rollback below;
that bounds the outage well inside the observer's 20 minutes.

The sequence is not atomic. If the import succeeds and the publish fails, the live
router stays overwritten and inactive; if the publish succeeds and the restart
fails, n8n may be stopped. So the sequence below runs each stage on its own, stops
at the first failure, prints which stage failed and what to run, and its exit status
is real (it is run in a session, not in a one-line ssh with a trailing `echo` that
would turn a failure into success).

Before the import, read and save three things:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'ls -l "$HOME/.config/doppler-siem/router-path" && cut -c1-15 "$HOME/.config/doppler-siem/router-path"; echo'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n n8n --help | grep -E "publish|update:workflow"'
```

The saved copy is written to a private directory first, then installed with an
explicit mode 600, and the chain refuses to go on unless the mode and the content
check out (the container-side mode of the export is not under your control, so
`umask` alone is not enough). In a session on LOGGING_BOX:

```
owner_chk_vars && umask 077 && D="$(mktemp -d)" && docker exec n8n n8n export:workflow --id="$ROUTER_ID" --output=/tmp/router-before.json && docker cp n8n:/tmp/router-before.json "$D/r.json" && docker exec n8n rm -f /tmp/router-before.json && [ ! -L "$HOME/router-before.json" ] && install -m 600 "$D/r.json" "$HOME/router-before.json" && rm -rf "$D" && [ "$(stat -c %a "$HOME/router-before.json")" = 600 ] && test -s "$HOME/router-before.json" && grep -q "$ROUTER_ID" "$HOME/router-before.json" && N="$(python3 -c 'import json,sys; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; print(len(d["nodes"]))' < "$HOME/router-before.json")" && [ "$N" -gt 0 ] && echo "saved copy ok: $HOME/router-before.json, $N nodes"
```

Write down the node count it prints: the rollback verification below compares
against it. DECIDED 2026-11-20 (owner: "Rehearse on a scratch n8n first"): the
export-to-import round trip of this n8n version has never been run here, so the
rollback is unproven until the owner runs the rehearsal in 6.0a below, before the
first live import. Until then the export format that `owner_router_rollback` expects
(a workflow array or one object, with a `nodes` list) is INFERRED, not VERIFIED: the
rehearsal is what can verify it. If you skip it, the step 2 archive is the only proven
restore, and the live import carries that risk.

- The first must list the file as `-rw-------` and print `grafana-alerts-`: that file
  is the live Grafana path. If it is missing, the import makes a NEW Grafana path and
  Grafana's contact point (still on the old one) gets 404 on every alert: stop and
  find the file (the helper reads it from `SIEM_CONFIG_DIR`, default
  `$HOME/.config/doppler-siem`; the user running the import must be the user who owns
  it) before going on.
- The second must show `publish:workflow`. On an older n8n only `update:workflow`
  exists: use `update:workflow --id=ROUTER_ID --active=true` in the command below
  (VERIFIED: `docs/game-day.md` says the name differs between versions).
- The saved copy (the `export:workflow` flags are INFERRED; check `n8n export:workflow
  --help`) lives at `$HOME/router-before.json`, mode 600, because it holds the
  private webhook path. It stays on the box; delete it with `rm -f
  "$HOME/router-before.json"` after step 4 passes. The step 2 archive is the older
  fallback.

Now the import, publish and restart, in the same session (the session variables are
set and `owner_chk_vars` printed `variables ok`). It is defined as one function so the
status `R` cannot be lost between separately pasted lines. Each stage runs only if the
one before it succeeded, a failure prints the stage, the recovery and the limit, and
the function returns the real status after printing `chain exit code: N`:

```
unset -f owner_router_chain 2> /dev/null
owner_router_chain() {
  : "runbook-block-router-chain-v3"
  local R
  owner_chk_vars || return 1
  ( cd "$REPO_DIR" && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-setup-alert-router.py --workflow n8n/grafana-alert-router.json "$ROUTER_ID" --error-workflow-id "$HANDLER_ID" )
  R=$?
  [ $R -eq 0 ] || echo "FAILED stage 1 of 3 (import), exit $R: the live router may be unchanged or half written; run n8n list:workflow, and if it is not active use owner_router_rollback within 5 minutes"
  if [ $R -eq 0 ]; then docker exec n8n n8n publish:workflow --id="$ROUTER_ID"; R=$?; [ $R -eq 0 ] || echo "FAILED stage 2 of 3 (publish), exit $R: the router is overwritten and INACTIVE. Retry this publish once, then docker restart n8n; if it fails again run owner_router_rollback within 5 minutes"; fi
  if [ $R -eq 0 ]; then docker restart n8n; R=$?; [ $R -eq 0 ] || echo "FAILED stage 3 of 3 (restart), exit $R: the router is published but n8n may be stopped. Run docker start n8n, then docker ps --filter name=n8n; if it does not come up healthy within 5 minutes run owner_router_rollback"; fi
  echo "chain exit code: $R"
  return $R
}
OWNER_SUM_CHAIN="$(declare -f owner_router_chain | sha256sum | cut -d' ' -f1)"
if [ "$OWNER_FRESH" = 1 ] && [ "$(declare -f owner_router_chain | sha256sum | cut -d' ' -f1)" = "$OWNER_SUM_CHAIN" ]; then owner_router_chain; else echo "STALE FUNCTION: a read-only or older owner_router_chain exists; open a fresh bash shell, set the session variables and paste again"; false; fi
echo "owner_router_chain returned $?"
```

`chain exit code: 0` (and `owner_router_chain returned 0`) is the only success. Expected output lines (VERIFIED: the
script and runbook section 3):
`workflow import exit code: 0`, `new webhook path saved (mode 600): ...`,
`expiry watch webhook path saved (mode 600): ...` and `error workflow set: True`,
then the publish output and the container name from `docker restart`. The helper
reuses the saved
Grafana path (`router-path`) when it looks right and makes the expiry path
(`expiry-watch-alerts-` plus 24 URL-safe characters) the first time, writing it mode
600 to `expiry-path` in the same config directory (VERIFIED: script). The
committed `Expiry Watch Webhook` node ships disabled with a placeholder path
(`PLACEHOLDER-set-by-the-import-helper`); only the helper enables it, with the
private path. Read back that there is still exactly one router (no duplicate made
by a wrong id) and the heartbeat resumes (step 1):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n n8n list:workflow'
```

ROLLBACK of this item (re-import the exported live router, publish it, restart,
verify). Check the saved copy BEFORE the sequence above touches anything: the file
exists, is mode 600 and names `ROUTER_ID` (the "saved copy ok" line). The saved file
is a workflow array or one object depending on the n8n version; the first import
format is NOT verified, so if the import below rejects it, restore from the step 2
archive. Same session, same stop-at-the-first-failure shape:

```
unset -f owner_router_rollback 2> /dev/null
owner_router_rollback() {
  : "runbook-block-router-rollback-v3"
  local R F T NODES_BEFORE NODES_AFTER COUNT_PY
  COUNT_PY='import json,sys; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; print(len(d["nodes"]))'
  owner_chk_vars || return 1
  F="$HOME/router-before.json"
  if [ ! -s "$F" ] || [ -L "$F" ] || [ "$(stat -c %a "$F")" != 600 ]; then echo "ROLLBACK STOP: the saved copy is missing, a symlink or not mode 600; restore from the step 2 archive"; echo "rollback exit code: 1"; return 1; fi
  NODES_BEFORE="$(python3 -c "$COUNT_PY" < "$F")"; R=$?
  case "$NODES_BEFORE" in ''|*[!0-9]*|0) R=1;; esac
  if [ $R -ne 0 ]; then echo "ROLLBACK STOP: the saved copy is not a workflow with a positive node count (got '${NODES_BEFORE}'); nothing was touched; restore from the step 2 archive"; echo "rollback exit code: 1"; return 1; fi
  R=0
  docker cp "$F" n8n:/tmp/router-before.json; R=$?; [ $R -eq 0 ] || echo "ROLLBACK FAILED at: copy into the container (exit $R)"
  if [ $R -eq 0 ]; then docker exec n8n n8n import:workflow --input=/tmp/router-before.json; R=$?; [ $R -eq 0 ] || echo "ROLLBACK FAILED at: import (exit $R): the saved file format was not accepted, restore from the step 2 archive"; fi
  docker exec n8n rm -f /tmp/router-before.json /tmp/router-after.json > /dev/null 2>&1
  if [ $R -eq 0 ]; then docker exec n8n n8n publish:workflow --id="$ROUTER_ID"; R=$?; [ $R -eq 0 ] || echo "ROLLBACK FAILED at: publish (exit $R)"; fi
  if [ $R -eq 0 ]; then docker restart n8n; R=$?; [ $R -eq 0 ] || echo "ROLLBACK FAILED at: restart (exit $R): run docker start n8n"; fi
  if [ $R -eq 0 ]; then sleep 30; [ "$(docker exec n8n n8n list:workflow | grep -c "^$ROUTER_ID")" = 1 ]; R=$?; [ $R -eq 0 ] || echo "ROLLBACK FAILED at: verify exists (the router id is not listed exactly once)"; fi
  if [ $R -eq 0 ]; then docker exec n8n n8n list:workflow --active=true | grep -q "^$ROUTER_ID"; R=$?; [ $R -eq 0 ] || echo "ROLLBACK FAILED at: verify active (the router is not listed as active)"; fi
  if [ $R -eq 0 ]; then T="$(mktemp -d)" && docker exec n8n n8n export:workflow --id="$ROUTER_ID" --output=/tmp/router-after.json > /dev/null && docker cp n8n:/tmp/router-after.json "$T/after.json" && NODES_AFTER="$(python3 -c "$COUNT_PY" < "$T/after.json")" && [ "$NODES_AFTER" = "$NODES_BEFORE" ]; R=$?; rm -rf "$T"; docker exec n8n rm -f /tmp/router-after.json > /dev/null 2>&1; [ $R -eq 0 ] || echo "ROLLBACK FAILED at: verify node count (expected $NODES_BEFORE, the live export gave '${NODES_AFTER:-nothing}' or a command failed)"; fi
  if [ $R -eq 0 ]; then echo "rollback verified: router listed once, active, $NODES_BEFORE nodes; now run the step 1 presence check and wait for the next heartbeat ping"; else echo "do not leave n8n stopped (docker start n8n) and restore from the step 2 archive (docs/backup-restore.md)"; fi
  echo "rollback exit code: $R"
  return $R
}
OWNER_SUM_ROLLBACK="$(declare -f owner_router_rollback | sha256sum | cut -d' ' -f1)"
if [ "$OWNER_FRESH" = 1 ] && [ "$(declare -f owner_router_rollback | sha256sum | cut -d' ' -f1)" = "$OWNER_SUM_ROLLBACK" ]; then owner_router_rollback; else echo "STALE FUNCTION: a read-only or older owner_router_rollback exists; open a fresh bash shell, set the session variables and paste again"; false; fi
echo "owner_router_rollback returned $?"
```

Every stage stops the rest at the first failure, the failing stage is named, and the
function returns that real status (`rollback exit code: N`; only `0` is success). The
container-side temporary files are removed on every path. The checks after the restart
are read only and print names and counts only: the router id listed once, listed as
active, and the same node count as the saved file. The node count is the length of the
`nodes` array, read with `python3` from the saved file and from a fresh export of the
live router; each command's status is captured separately, an empty, non-numeric or
zero count stops the rollback before anything is touched, and a failed live read can no
longer look like a match. The `list:workflow --active=true` flag is INFERRED:
check `n8n list:workflow --help`. If you cannot confirm them, OWNER DECISION: check by
hand that the router is listed once, is active in the n8n interface and has the same
number of nodes, then the heartbeat ping arrives (step 1), and record it. The
rollback restores the workflow as it was exported. It does not undo the files
`router-path` and `expiry-path` (they only hold paths).

**4. Post-import checks.** First the placeholder path must serve nothing (the
point is that the committed node is disabled). That n8n registers no webhook for
a disabled trigger node is UNVERIFIED against a live n8n (VERIFIED: stated as
unverified in `docs/expiry-watch.md`); this check is how you find out:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Content-Type: application/json" -d "{}" http://127.0.0.1:HOST_PORT/webhook/PLACEHOLDER-set-by-the-import-helper'
```

Expect `404`. Anything else: stop, deactivate the workflow and report; do not use
the endpoint. Then confirm the real path rejects a call with no secret. The private
path is an address, not a credential, but keep it out of git and chat (VERIFIED:
`docs/expiry-watch.md`), so it is read on the box and never printed:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'P=$(cat "$HOME/.config/doppler-siem/expiry-path") && curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Content-Type: application/json" -d "{}" "http://127.0.0.1:HOST_PORT/webhook/$P"'
```

(`$HOME/.config/doppler-siem` is the helper's default config directory, VERIFIED:
runbook variable table; use yours if you changed it.) Expect `403` (VERIFIED: a
denied call is answered 403 with a fixed body). A real accepted call comes only
from the real run in 6d and the limit test in 6.3, which use the real secret. The
dry run in 6c never posts and never reads the secret.

**5. Point the watch at it.** In `/etc/expiry-watch/expiry-watch.toml` set
`[router].url` to `http://127.0.0.1:HOST_PORT/webhook/EXPIRY_WATCH_PRIVATE_PATH`
(the path from `expiry-path`; plain http is allowed for localhost, VERIFIED) and
keep `[router].token_env = "EXPIRY_WATCH_ROUTER_TOKEN"`. Never commit the path.
The config file is created in 6a, so this edit happens there, after the files exist.
The file `expiry-path` belongs to the user who ran the helper while the config
belongs to SERVICE_ACCOUNT; copy the one line by hand (read it with `cat` in a session
and paste it into the `sudoedit` of 6a; it stays out of command lines you save).

**6. Ingress limits (Q12, ANSWERED 2026-11-20, issue #157).** The watch posts
to the loopback port in 6.0, which does not pass a reverse proxy, so a proxy
cannot enforce limits on this path. They live in the watch and in the router
instead (VERIFIED: `docs/expiry-watch.md`, "Request limits"): the watch refuses a
body over 16 KB, waits 2 seconds between posts and posts at most 15 times per
run; the router's `Check Expiry Secret` node denies a body over 16 KB, a call
under 1 second after the last accepted one and more than 30 accepted calls in 10
minutes. No owner step is needed for these once the router is re-imported. After
the first import, check the items that doc marks UNVERIFIED (that the Code node
can read the workflow static data in a production execution, which the check
needs or it denies every call, that two overlapping executions do not both read
the old counter, that the counter persists across executions, and that the
`content-length` header reaches it).
A denied call still starts one workflow execution, and anyone who can reach n8n's
webhook address on the siem network or LAN can still cause that. n8n's own body
limit is `N8N_PAYLOAD_SIZE_MAX`, default 16 (MiB per the n8n docs, read
2026-11-20). Section 6.2 below sets it; the router's Code node cannot see the raw
body, so that setting is the real body cap.

**Rotate.** Generate a new value, store it with the command in item 1 (it
replaces the old one), then restart the n8n container so it reads the new
environment (VERIFIED: `docs/expiry-watch.md` owner step 5): recreate n8n with the
SAFE N8N RECREATE of 6.0 (its second call). Both sides change together; between the
n8n restart and the next watch run the watch must already hold the new value. The
dry run in 6c does NOT confirm that: it never reads the secret (VERIFIED:
`scripts/expiry_watch.py` reads the token only when it posts). The first real run
or the 6.3 test does.

**Revoke the watch alone.** Empty the router's variable (VERIFIED: `docs/expiry-watch.md`
owner step 5): set the n8n entry to an empty value, or delete
`EXPIRY_WATCH_ROUTER_TOKEN` from the dev config so the substitution is empty, and
recreate n8n. The endpoint then denies every call with 403. Grafana alerts are
unaffected (VERIFIED). A full rollback of this section: restore the backed-up
n8n compose file, recreate n8n, and re-import the previous workflow from the step
2 backup archive or deactivate the `Expiry Watch Webhook` node in the n8n
interface.

### 6.2 Cap request bodies at n8n: N8N_PAYLOAD_SIZE_MAX (LIVE, restarts n8n)

Target: the n8n container on LOGGING_BOX, compose file
`/opt/n8n/docker-compose.yml` (VERIFIED by the lead 2026-11-20: n8n runs from
that file and its environment list has no `N8N_PAYLOAD_SIZE_MAX`, so n8n uses
its default of 16 MiB).

Change: add `N8N_PAYLOAD_SIZE_MAX=1` (MiB) after the
`N8N_BLOCK_ENV_ACCESS_IN_NODE=false` line and recreate the container. The n8n
docs (https://docs.n8n.io/hosting/configuration/environment-variables/endpoints/,
read 2026-11-20) give the unit as MiB, default 16, and say a restart is
required. They say nothing about fractional values or which request types the
setting limits (UNVERIFIED both). This is the real cap on the raw request,
because the router's Code node runs after n8n has parsed the body and cannot see
the raw bytes. The owner applied this value live on 2026-11-20 with the command
below; the section is the record and the command to repeat it on another host.

Run it from a real terminal. `sudo` needs a tty, so do not run it with a `!`
prefix or over a no-tty ssh.

To repeat it (a new host, or after a restore), do NOT reuse the one-line command
below: it overwrites `.bak-payload` without looking and recreates n8n without
`doppler run`. Use two steps instead. First the edit, which refuses unless this run's
backup exists and matches (a name that already exists stops the chain):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'B="/opt/n8n/docker-compose.yml.bak-payload-$(date -u +%Y%m%dT%H%M%SZ)" && sudo test ! -e "$B" && sudo cp -p /opt/n8n/docker-compose.yml "$B" && sudo cmp /opt/n8n/docker-compose.yml "$B" && echo "backup $B ok" && sudo grep -q "N8N_BLOCK_ENV_ACCESS_IN_NODE=false" /opt/n8n/docker-compose.yml && ! sudo grep -q "N8N_PAYLOAD_SIZE_MAX" /opt/n8n/docker-compose.yml && sudo sed -i "/- N8N_BLOCK_ENV_ACCESS_IN_NODE=false/a\      - N8N_PAYLOAD_SIZE_MAX=1" /opt/n8n/docker-compose.yml && cd /opt/n8n && sudo docker compose config -q && sudo grep -n N8N_PAYLOAD_SIZE_MAX /opt/n8n/docker-compose.yml'
```

Then recreate with the SAFE N8N RECREATE of 6.0 and read back
`N8N_PAYLOAD_SIZE_MAX=1` with `docker inspect n8n --format "{{range .Config.Env}}{{println .}}{{end}}" | grep N8N_PAYLOAD`
and the healthy status with `docker ps --filter name=n8n --format "{{.Status}}"`.
The command as it was actually run on 2026-11-20, kept as the record (note its `;`
before the last command hides a failure of the chain, which is another reason not to
reuse it):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo cp -p /opt/n8n/docker-compose.yml /opt/n8n/docker-compose.yml.bak-payload && sudo sed -i "/- N8N_BLOCK_ENV_ACCESS_IN_NODE=false/a\      - N8N_PAYLOAD_SIZE_MAX=1" /opt/n8n/docker-compose.yml && cd /opt/n8n && sudo docker compose config -q && sudo docker compose up -d n8n && sleep 15 && docker inspect n8n --format "{{range .Config.Env}}{{println .}}{{end}}" | grep N8N_PAYLOAD; docker ps --filter name=n8n --format "{{.Status}}"'
```

Evidence (VERIFIED by the lead 2026-11-20 after the owner ran it): the read-back
printed `N8N_PAYLOAD_SIZE_MAX=1` and `docker ps` showed a healthy container. On
a new run, expect the same two lines; no `N8N_PAYLOAD_SIZE_MAX` line means the
`sed` found no anchor line, so restore the backup (below) and edit by hand. The
backup name `.bak-payload` is fixed: if that file already exists, a second run
overwrites the pre-change copy, so check with `ls` first and pick another name.

That run recreated n8n WITHOUT the `dev_network` wrapper, and its read-back did not check the
two things a recreate can drop. Read them back now, and after any repeat of this
section (INFERRED hazard, see the RESOLVED decision in 6.1 item 2). The heartbeat and
(once 6.1 is done) expiry variables must still say `set`, and `n8n` must still be
on the siem network:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n sh -c "if [ -n \"\$HEARTBEAT_PING_URL\" ]; then echo HEARTBEAT_PING_URL set; else echo HEARTBEAT_PING_URL unset; fi; echo HEARTBEAT_KIND=\${HEARTBEAT_KIND:-healthchecks}"'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker network inspect SIEM_NETWORK --format "{{range .Containers}}{{.Name}} {{end}}"'
```

`HEARTBEAT_PING_URL unset` means the heartbeat is off: the observer reports down
after about 20 minutes. Recreate n8n with the SAFE N8N RECREATE of 6.0
and check again. `n8n` missing from the second list means Grafana cannot
reach it: reattach it as in `docs/live-deploy-runbook.md`, "Keep n8n on the siem
network". Also confirm the next heartbeat ping arrives (step 1).

Blast radius: recreating n8n interrupts every webhook receiver for about 15
seconds (Grafana, Wazuh and CrowdSec notices that arrive in that window are not
received). The limit is instance-wide, so a Wazuh or CrowdSec payload over 1 MiB
would be refused. How large real payloads get is UNVERIFIED; if a sender starts
failing with 413 after this change, raise the value.

Rollback: copy the backup over the file (the 2026-11-20 backup is
`.bak-payload`; a repeat run's is the `$B` it printed), then recreate with the SAFE
N8N RECREATE of 6.0, never a plain `docker compose up`:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo cp -p /opt/n8n/docker-compose.yml.bak-payload /opt/n8n/docker-compose.yml && sudo cmp /opt/n8n/docker-compose.yml.bak-payload /opt/n8n/docker-compose.yml && echo "compose file restored"'
```

### 6.3 Test the router limits after the import (LIVE, UNVERIFIED)

Run this after the router is imported and active (6.1). Nothing here is
confirmed against a live n8n: the live rate-limit counter (the workflow static
data read in the `Check Expiry Secret` node) has not been exercised, and a
denied call is answered 403 by design (VERIFIED: `docs/expiry-watch.md`).

Target: the `Expiry Watch Webhook` endpoint on LOGGING_BOX. Change: none to the
system, it sends test notices. Blast radius: each call starts one workflow
execution, and every ACCEPTED call posts one message to Discord (no phone: the
body below has no `phone` label). The window test in item 3 therefore posts about
30 messages; the dry run of the watch does not post and cannot stand in for this
test (it never calls the router).

DECIDED 2026-11-20 (owner: "Skip it for now"): item 3 (about 30 Discord messages in
a minute) is skipped for now. Items 1 and 2 are the evidence for the 1 second rule,
and the 30-in-10-minutes rule waits for real use. Item 3 stays below as an optional
later step; nothing else depends on it.

The secret never goes on a command line: the commands below pass the header on
standard input (`curl -H @-`, VERIFIED to read headers from stdin with curl 8.21,
run 2026-11-20) from the `printf` built-in, inside the `dev_network` wrapper, so the value is only
in the environment of that one child process. Run them as yourself, in a session on
LOGGING_BOX with the token and wrapper of step 0b.5 (the
`SERVICE_ACCOUNT` files are not needed here). The body is exactly the shape the
watch builds (VERIFIED: `tests/python/test_router_expiry_secret.py`, `_expiry_body`):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX
```

In that session:

```
umask 077
printf '%s' '{"receiver":"expiry-watch","status":"firing","alerts":[{"status":"firing","labels":{"alertname":"Expiry watch: limit-test","severity":"info","expiry_watch":"true","item":"limit-test","kind":"test","stage":"30"},"annotations":{"summary":"limit test","description":"limit test"},"fingerprint":"0123456789abcdef0123456789abcdef"}]}' > "$HOME/notice.json"
```

1. One authenticated, valid notice. Expect `200` and one message in Discord:

```
"$HOME/bin/siem-net-run" --require EXPIRY_WATCH_ROUTER_TOKEN -- sh -c 'printf "Authorization: Bearer %s\n" "$EXPIRY_WATCH_ROUTER_TOKEN" | curl -s -o /dev/null -w "%{http_code}\n" -X POST -H @- -H "Content-Type: application/json" --data-binary @"$HOME/notice.json" "http://127.0.0.1:HOST_PORT/webhook/$(cat "$HOME/.config/doppler-siem/expiry-path")"'
```

2. A fast burst: three calls started at the same moment. The router accepts one
   call and denies a call under 1 second after it, so expect one `200` and two
   `403` (a second `200` means two overlapping executions read the old counter, a
   finding):

```
"$HOME/bin/siem-net-run" --require EXPIRY_WATCH_ROUTER_TOKEN -- sh -c 'for i in 1 2 3; do printf "Authorization: Bearer %s\n" "$EXPIRY_WATCH_ROUTER_TOKEN" | curl -s -o /dev/null -w "%{http_code}\n" -X POST -H @- -H "Content-Type: application/json" --data-binary @"$HOME/notice.json" "http://127.0.0.1:HOST_PORT/webhook/$(cat "$HOME/.config/doppler-siem/expiry-path")" & done; wait'
```

3. The window (only if you chose to run it): 32 calls, 2 seconds apart, then the
   count per status. Calls accepted in items 1 and 2 count toward the 30, so
   `200` appears 30 minus those times and the rest are `403`:

```
"$HOME/bin/siem-net-run" --require EXPIRY_WATCH_ROUTER_TOKEN -- sh -c 'for i in $(seq 1 32); do printf "Authorization: Bearer %s\n" "$EXPIRY_WATCH_ROUTER_TOKEN" | curl -s -o /dev/null -w "%{http_code}\n" -X POST -H @- -H "Content-Type: application/json" --data-binary @"$HOME/notice.json" "http://127.0.0.1:HOST_PORT/webhook/$(cat "$HOME/.config/doppler-siem/expiry-path")"; sleep 2; done | sort | uniq -c'
```

4. Evidence to record: the status code for every call and the number of messages
   that reached Discord (it must equal the number of `200` results). n8n lists NO
   execution for these calls: the router stores neither successful nor failed
   executions by design (`saveDataSuccessExecution` and `saveDataErrorExecution`
   are `none`; VERIFIED: `docs/update-alerting.md`), so there is nothing to read in
   the executions list. If every call is `403`, the Code node cannot read the static
   data or the secret does not match (compare with the presence check in 6.1 item
   2, and see the UNVERIFIED list in 6.1, item 6); if the fast burst has more than
   one `200`, the counter is not safe under overlap.

Clean up the body file when you are done:

```
rm -f "$HOME/notice.json"
```

Rollback: nothing to undo; wait 10 minutes for the counter window to clear.

### 6a. Private config folder and copies (on LOGGING_BOX)

The folder must be writable only by the job user (VERIFIED: "Paths and symbolic
links"). Keep it outside the repo, since the router URL contains the private
webhook path.

```
sudo install -d -m 700 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT /etc/expiry-watch
sudo install -m 600 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT REPO_DIR/docs/expiry-watch.example.toml /etc/expiry-watch/expiry-watch.toml
sudo install -m 600 -o SERVICE_ACCOUNT -g SERVICE_ACCOUNT REPO_DIR/docs/expiry-watch-registry.example.toml /etc/expiry-watch/expiry-watch-registry.toml
sudoedit /etc/expiry-watch/expiry-watch.toml
```

Edit (the example values are placeholders and several will fail until replaced):

- `[router].url`: the localhost URL from section 6.0 plus the expiry watch's
  private path from section 6.1,
  `http://127.0.0.1:HOST_PORT/webhook/EXPIRY_WATCH_PRIVATE_PATH` (the path is in
  the `expiry-path` file in the helper's config directory, not the Grafana
  `router-path`).
- `path` of the registry provider: `expiry-watch-registry.toml`. List your real
  items in the registry file (`name`, `kind`, `expires` as `YYYY-MM-DD`,
  `owner`, `runbook`).
- Replace the example `tls` provider host with real hosts, or delete the block.
  Delete the `grafana_sa_tokens` and `doppler_tokens` blocks, the `[matrix]` and
  `[email]` tables and any route that names them, until you are ready for them.
- `[routes]`: keep `pushover` out of every route until step 8 is finished; the
  router only pages the phone when Pushover is enabled (VERIFIED: "Channels and
  routing"), so a premature `pushover` is harmless but misleading. A notice
  routed only to `matrix` or `email` does not touch the router and so does not
  go to Discord (VERIFIED).

### 6b. Secrets by variable name

The config only ever names variables, never values (VERIFIED). The names:

| Variable | Used for | Source doc |
|----------|----------|-----------|
| `EXPIRY_WATCH_ROUTER_TOKEN` | Router bearer secret | `expiry-watch.md`, quick start step 2 |
| `EXPIRY_WATCH_GRAFANA_TOKEN` | `grafana_sa_tokens` provider | example config |
| `EXPIRY_WATCH_DOPPLER_TOKEN` | `doppler_tokens` provider | example config |
| `EXPIRY_WATCH_MATRIX_TOKEN` | `[matrix]` | example config |
| `EXPIRY_WATCH_SMTP_USER`, `EXPIRY_WATCH_SMTP_PASSWORD` | `[email]` login | example config |

Set only the ones the config uses, to the dev_network config, each with
`--silent` and ending in `> /dev/null`.

`EXPIRY_WATCH_ROUTER_TOKEN` is already set by section 6.1, item 1 (a generated
value, never typed and never the Grafana secret); do not set it again here. For
any other variable you use, such as `EXPIRY_WATCH_MATRIX_TOKEN`:

```
read -rs -p "Value for VARIABLE_NAME: " VAL; echo
printf '%s' "$VAL" | doppler secrets set VARIABLE_NAME --project homelab --config dev_network --silent > /dev/null
unset VAL
```

### 6c. Dry run first (changes nothing, posts nothing, saves nothing)

The config folder is mode 700 and owned by `SERVICE_ACCOUNT` (6a), so your own
user cannot read it: run the watch as that account with `sudo -u`. The account's
read-only Doppler token (0c.3) goes into the environment of the one `doppler run`
child process from its file, never onto a command line (the `cat` argument is only
the file path). `REPO_DIR` must be readable by the account (step 0a makes it so):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo -u SERVICE_ACCOUNT sh -c "cd REPO_DIR && DOPPLER_TOKEN=\$(cat /var/lib/SERVICE_ACCOUNT/doppler-token) doppler run --no-check-version --config-dir /var/lib/SERVICE_ACCOUNT/.doppler -- python3 scripts/expiry_watch.py --config /etc/expiry-watch/expiry-watch.toml --dry-run; echo \"exit code: \$?\""'
```

(`doppler run` form VERIFIED in `docs/update-alerting.md`; `--config-dir` and
`--no-check-version` are VERIFIED in `scripts/live-deploy/siem-run`; the token
variable and the use with this script are INFERRED, see 0c.3. The token is scoped to
`dev_network`, so no `--project` or `--config` is needed.)

The dry run never reads the router secret (VERIFIED: `scripts/expiry_watch.py` looks
the token up only when it posts), so a clean dry run does not prove the secret or
the router URL. Section 6.3 and the first real run in 6d do.

Watch:

- Exit code `0` ok, `1` a provider or delivery failed (details on stderr), `2` a
  config problem; a missing or malformed secret gives `2` only on a real run
  (VERIFIED).
- The output lists the notices that are due and the JSON it would post. Check the
  item names, dates and owner lines are the real ones.
- A TLS provider error is a real finding, not a date (VERIFIED: "tls").
- Expect a first run to show many notices at once for items already inside a
  threshold; only the lowest crossed threshold per item fires (VERIFIED).

### 6d. First real run, then schedule

Only when the dry run is clean and the route is the one you want. A real run
posts real messages to Discord, and an unwanted message cannot be recalled:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'sudo -u SERVICE_ACCOUNT sh -c "cd REPO_DIR && DOPPLER_TOKEN=\$(cat /var/lib/SERVICE_ACCOUNT/doppler-token) doppler run --no-check-version --config-dir /var/lib/SERVICE_ACCOUNT/.doppler -- python3 scripts/expiry_watch.py --config /etc/expiry-watch/expiry-watch.toml; echo \"exit code: \$?\""'
```

An exit code `2` with `config error: set the environment variable
EXPIRY_WATCH_ROUTER_TOKEN` means the token did not reach the process (check 6.1 item
1 and the account's token file); a `403` from the router in the stderr text means the
router's `EXPIRY_WATCH_ROUTER_SECRET` and the token differ or env access is blocked
(6.1 item 2).

Confirm the messages arrive and the state file `/etc/expiry-watch/expiry-watch-state.json`
exists with mode 0600 (VERIFIED). Then schedule it on LOGGING_BOX with either a
systemd service and timer or a cron entry; both are given in
`docs/expiry-watch.md`, "Scheduling", and the choice is yours. Whichever you
pick, the job runs on the box, as the same user that owns the config folder, and
reads its secrets only from the single dev config by wrapping the command in
`doppler run` with the account's `dev_network` token, as in 6c (the secrets are
named by variable only; no value goes in the unit, the cron line or the config). That
doc's examples instead read the router secret from an `EnvironmentFile` (mode
0600, owned by the job user); using `doppler run` in place of it is INFERRED, and
needs the Doppler CLI logged in for that user (non-interactive login for a
scheduled job is not covered by any repo doc). The doc also warns that nothing alerts you if the schedule stops;
use job monitoring (VERIFIED).

Rollback: disable the timer or remove the cron line. Deleting the state file
makes the next run re-send everything due (VERIFIED: state semantics). Messages
already sent stay sent.

## Step 7. Game-day scenarios, dry run only (LIVE read-only on the box)

Request item 7, first half. Source: `docs/game-day.md` ("Safety model",
"Configuration", "Scenarios"). Dry run is the default and changes nothing
(VERIFIED).

Prerequisites: steps 1 and 4 (so the failure alert and heartbeat exist to
observe). The config file lives outside the repo.

Make the config (a file kept outside the repository; `router_path` is the private
webhook path, so mode 0600):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'umask 077 && mkdir -p "$HOME/.config/gameday" && cat > "$HOME/.config/gameday/gameday.toml" <<EOF
n8n_container = "n8n"
grafana_container = "grafana"
heartbeat_host = "OBSERVER_HOSTNAME"
router_workflow_id = "ROUTER_ID"
router_path = "PRIVATE_WEBHOOK_PATH"
EOF'
```

Replace `OBSERVER_HOSTNAME` (the host of the observer's ping URL),
`ROUTER_ID` (the n8n id of the router) and `PRIVATE_WEBHOOK_PATH` (the contents
of the `router-path` file) before running, with an editor if you prefer. All
three are required by their scenarios (VERIFIED: configuration table).

List and preview each scenario, in this order from least to most disruptive
(the order is INFERRED from the scenario descriptions):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && python3 scripts/gameday.py list'
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && for S in wrong-header discord-unreachable phone-unreachable heartbeat-silent router-inactive n8n-down grafana-down; do echo "=== $S"; python3 scripts/gameday.py $S --config "$HOME/.config/gameday/gameday.toml"; done'
```

Read each plan: what it would do, what you should observe, how to revert. Check
the revert command for each. The `router-inactive` plan uses the `n8n
update:workflow` CLI whose name differs between n8n versions (VERIFIED:
`docs/game-day.md`, "Not verified"); run `docker exec n8n n8n --help` and confirm
the subcommand before step 10.

Watch: every plan exits 0 and prints a plan, no step runs. `--apply` alone is
refused with exit 2 (VERIFIED), which is the safe failure.

Rollback: nothing changed.

## Step 8. Pushover and the phone (LIVE, pages a real phone)

Request item 9. Source: `docs/update-alerting.md` ("Pushover (phone push)",
"Pushover credential", "Enable it", "Manual pre-deploy checklist") and
`docs/live-deploy-runbook.md` section 4 (optional phone test).

What the docs say: Pushover is off by default; one constant,
`PUSHOVER_ENABLED`, in the `Build Pushover Payload` Code node turns it on; only
alerts with `phone=true` reach it; priority 1 bypasses quiet hours; priority 2
(emergency) repeats until acknowledged (VERIFIED).

Owner decision: the phone is muted only while the live game-day
and failure tests run, so test pages wake no one, and it is unmuted afterward.
Real paging stays fully on at all other times. The mute and unmute procedure is
8b and 8c below. This doc does not describe Pushover's or the phone's own
screens, because no repo doc verifies them; use whatever mute control you
normally use and send a screenshot if you want it written down.

Prerequisites for enabling: the credential `pushover-api` exists
in n8n and the Doppler values `PUSHOVER_API_KEY` and `PUSHOVER_USER_KEY` exist
(VERIFIED: `docs/update-alerting.md`, which says they already exist in
`prd_network`; the live check is `siem-run ... --check` in step 0).

### 8a. Enable Pushover in the router

In the n8n web interface open the router workflow, open the
`Build Pushover Payload` Code node, change `const PUSHOVER_ENABLED = false;` to
`true` (VERIFIED: "Enable it", item 4), save and keep the workflow active. An
alternative is re-running the import with `--pushover-on` and the existing
ids, `--workflow n8n/grafana-alert-router.json ROUTER_ID --error-workflow-id
HANDLER_ID`, then publish and `docker restart n8n` (VERIFIED: runbook section
3), but whether a re-import keeps the private path and the active state is
INFERRED, so prefer the UI edit.

Test, using the documented script (VERIFIED: runbook section 4). The phone is
unmuted for this one, so you hear the first real pages:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-test-router.py --phone; echo "exit code: $?"'
```

It sends a priority 1 and a priority 2 message. Confirm both arrive, then cancel
the repeats:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-test-router.py --phone-resolve; echo "exit code: $?"'
```

Watch: no successful execution is listed in n8n afterward (VERIFIED: checklist
item 6), and the heartbeat still pings and never reaches the phone.

### 8b. Mute before the live tests (before step 10, and before any forced failure test)

Mute the phone's alert sound for Pushover just before you inject the first live
scenario in step 10, or before any step that sends test pages to the phone.
Tell anyone else who receives the pages. Muting changes nothing in the stack; it
only stops the phone from sounding.

WARNING: while the phone is muted, P1 pages are NOT delivered audibly. A real
emergency (priority 2, which repeats until acknowledged) will not wake you. Keep
the muted window as short as the tests, and never leave the phone muted: do 8c
the moment the last scenario is reverted and recovery is checked.

### 8c. Unmute after the tests and prove it rings

1. Unmute the phone.
2. Send one real test page and confirm it rings once:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-test-router.py --phone; echo "exit code: $?"'
```

3. Confirm the message arrived and the phone sounded once (this sends a priority
   1 and a priority 2 message; the doc script's behavior is VERIFIED in runbook
   section 4, so expect the emergency one to repeat), then cancel the repeats:

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && "$HOME/bin/siem-run" python3 -I scripts/live-deploy/n8n-test-router.py --phone-resolve; echo "exit code: $?"'
```

If it did not ring, the phone is still muted or Pushover is off: fix that before
you call the platform online.

Rollback: set `PUSHOVER_ENABLED` back to `false` in the same node (VERIFIED: it
is the shipped default). Emergency repeats already started stop with
`--phone-resolve` or by acknowledging in the app. Unmute the phone if you muted
it.

## Step 9. Deactivate the old router workflow after a day of normal traffic (LIVE)

Request item 8. Source: `docs/live-deploy-runbook.md` section 3 ("The old
router (if any) is untouched because a fresh import gets a new id") and the
deactivation commands in `docs/game-day.md` ("Rollback", deactivated router).

Prerequisites:

- Grafana's contact point `n8n-grafana-router` posts to the new router's private
  path (VERIFIED: runbook section 5 writes that path into the contact point).
- At least 24 hours of normal traffic on the new router with the heartbeat
  pinging steadily (step 1). Do not run any game-day live scenario in that
  window.
- The old router's live name and id are known (Q5). The new router must not be
  mistaken for it: the new one has the credential `grafana-webhook-auth` on its
  webhook node (VERIFIED).

Check the old router handled nothing in the last day in the n8n executions list
(INFERRED: it is only meaningful if the old workflow saved executions). Then
deactivate it. In the n8n interface, switch the old workflow to inactive, or use
the CLI with the old id (the subcommand name varies by n8n version, VERIFIED:
`docs/game-day.md`; check `docker exec n8n n8n --help` first):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'docker exec n8n n8n update:workflow --id=OLD_ROUTER_ID --active=false && docker restart n8n'
```

The restart is needed for the change to take effect (VERIFIED: game-day
`router-inactive` plan restarts n8n).

Watch: the next two heartbeat pings arrive (step 1); send one test alert with
`n8n-test-router.py` (no flags) and confirm Discord receives it; Grafana shows
no failed notification and the step 4 alert stays Normal.

Rollback: activate the old workflow again (n8n interface, or the same command
with `--active=true`) and `docker restart n8n`. Do not delete the old workflow
until you are sure, then delete it by hand in n8n.

## Step 10. Game-day live runs (LIVE, breaks things on purpose)

Request item 7, second half. Source: `docs/game-day.md` ("Safety model",
"Checklist", "Recording results", "Rollback").

Prerequisites:

- Steps 2, 4, 7, 8 and 9 done. The backup exists and was rehearsed.
- A maintenance window agreed, recipients told, a second person or channel
  watching (VERIFIED: checklist item 1).
- `router_workflow_id` in the config is the NEW router, and the CLI name for
  `router-inactive` was confirmed in step 7.
- The phone is muted per step 8b, just before the first live scenario. Unmute it
  per step 8c as soon as the last scenario is reverted and recovery is checked.
  A muted phone means P1 pages are NOT delivered audibly; never leave it muted.

Changes need both flags: `--apply --confirm-live` (VERIFIED). Run one scenario
at a time, from the checklist in the doc. Start with `wrong-header`, which sends
one webhook call with a made-up header (VERIFIED: no real secret is sent):

```
ssh -i KEY_FILE -o IdentitiesOnly=yes -t LOGGING_BOX 'cd REPO_DIR && python3 scripts/gameday.py wrong-header --config "$HOME/.config/gameday/gameday.toml" --apply --confirm-live --log "$HOME/.config/gameday/results.jsonl"; echo "exit code: $?"'
```

Expected: 401 or 403; anything else is a defect (VERIFIED). For each other
scenario use the same shape, with the baseline and recovery steps from the doc:

1. Baseline: `n8n-test-router.py` and confirm arrival, note the time.
2. Inject: `gameday.py SCENARIO --config ... --apply --confirm-live --log ...`.
3. Watch every OBSERVE line from the plan (Discord, phone, the observer's
   alert after period plus grace, the Grafana failure alert from step 4).
4. Revert: `gameday.py SCENARIO --revert --run-id ID --apply --confirm-live`.
   The three hosts scenarios (`discord-unreachable`, `phone-unreachable`,
   `heartbeat-silent`) print a run id at injection; keep it (VERIFIED).
5. Recovery check: a test alert arrives, the heartbeat resumes, and the
   observer shows up.

Expected outcomes (VERIFIED: the scenario table): `discord-unreachable` gives a
502 and one Pushover message from the error handler; `phone-unreachable` gives a
Discord alert plus a "phone delivery failed" notice; `heartbeat-silent` shows
the observer alerting after period plus grace; `n8n-down` shows the step 4
alert and the observer alert; `grafana-down` stops the heartbeat; and
`router-inactive` makes Grafana log a failed notification and stops the
heartbeat. Whether the stopped-container scenarios produce those alerts is "to
be confirmed on the first game day" (VERIFIED: "Not verified"). A scenario with
no alert is a finding: file an issue (VERIFIED).

Rollback, in order of preference (VERIFIED: `docs/game-day.md`, "Rollback"):

1. `gameday.py SCENARIO --revert --run-id ID --apply --confirm-live`.
2. By hand: `docker start n8n` or `docker start grafana` for a stopped
   container; activate the router again for `router-inactive` and restart n8n;
   remove the `# gameday-84-<id>` line from the n8n container's `/etc/hosts`
   (`docker exec n8n grep gameday-84 /etc/hosts` shows it).
3. Last resort for the hosts line: recreate n8n with
   `docker compose up -d --force-recreate n8n`, after checking that n8n stays on
   the siem network (VERIFIED: `docs/live-deploy-runbook.md`, "Keep n8n on the
   siem network").

After any rollback, send a baseline test alert and wait one heartbeat interval
for the observer to show up. When all scenarios are done, do step 8c (unmute and
confirm one test page rings).

## Not covered

- Matrix as a third P1 path: a later task, not part of this change (VERIFIED:
  `docs/channel-redundancy.md`).
- The OpenSearch snapshot job and the Wazuh indexer (separate backup, first
  half of `docs/backup-restore.md`).
- Production (prd) promotion of any new secret: its own step with its own
  approval, after you say the stack is live.
- The roadmap (`docs/roadmap.md`) carries no owner steps for this epic; none was
  cited. Check the epic's issue #62 for any step not listed here.
