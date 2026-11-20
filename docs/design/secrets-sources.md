# Design: secret sources (secret manager, env file, host store)

Status: DRAFT for the owner's decision. Docs only: no code, no configuration,
no live change. Tracked in issue #117 (epic #62), child of the deployment
variants epic #111. Companion design: [optional-components.md](optional-components.md).

Marking: **VERIFIED** means read from a file in this repository at master
c022559 (path given) or from a vendor page (URL and date read, 2026-11-19).
**INFERRED** means reasoned from those and not tested. Examples use
`example.com` and placeholder names only.

## 1. Problem

Issue #117: support the secret manager, plain env files and the host's own
store as secret sources, each with a documented least-privilege setup, and
prove the stack starts from each. A deployer with no secret manager account
must be able to run the stack, and an owner with one must not lose it.

## 2. Current state (VERIFIED)

| Fact | Source |
|---|---|
| Compose takes every stack secret by interpolation, `${VAR:?msg}` for each required one, so the secrets must be in the environment of the `docker compose` process or in `.env` next to the compose file | `docker/docker-compose.yml` (for example the grafana block, around line 215 to 230) |
| `.env.example` lists the secrets empty on purpose; README says keep `.env` mode 600 | `.env.example`, `README.md` ("Required secrets", line 250) |
| `scripts/check-env.sh` validates a `.env` file: refuses a symlink, reads it once through one file descriptor, refuses control bytes, rejects empty values and placeholders, prints names only. It checks a FILE, so it has no way to check secrets that live only in a process environment | `scripts/check-env.sh` |
| The one placeholder rule is `secret_is_placeholder` / `require_secret`, with a Python twin checked by a test | `scripts/lib-secrets.sh`, `tests/python/test_required_secrets.py` |
| `03-deploy.sh` requires a `.env` in the repo, runs `check-env.sh` on it, then copies it (cp or scp) to the deploy dir. With no `.env` it exits 1 | `scripts/03-deploy.sh` lines 116 to 133 |
| Scripts 04, 05, 08, 10 and 11 read the needed variable from the environment first and only when it is unset `source` the first existing `.env` among `/opt/siem/.env`, `<repo>/.env`, `<repo>/docker/.env`. `source` runs the file as shell, so `.env` must be trusted content | `scripts/04-apply-ism-policy.sh` lines 26 to 35, `10-snapshot-setup.sh`, `05-verify.sh`, `08-crowdsec-smoketest.sh`, `11-wazuh-grafana-readonly.sh` |
| `08b` and `render-alertmanager-config.sh` also look for `.env` in the same three places | `scripts/08b-init-opensearch-security.sh`, `scripts/render-alertmanager-config.sh` |
| `change-passwords.sh` WRITES new values into `/opt/siem/.env` and requires it to exist | `README.md` line 396 to 397 |
| Client-side secrets (`GRAFANA_PASS`, `N8N_API_KEY`, `N8N_PASSWORD`, `DISCORD_WEBHOOK_URL`) come from the shell, a secrets manager or Doppler; the deploy scripts have no fallback | `README.md` ("Required secrets", client-side table) |
| `siem-run COMMAND`: reads a read-only secret-manager service token from `$SIEM_CONFIG_DIR/token` (default `$HOME/.config/doppler-siem`), exits 2 if unreadable, exports it as `DOPPLER_TOKEN`, then `exec doppler run --config-dir "$CFG" --no-check-version --fallback-readonly -- "$@"`. Values exist only in the child environment | `scripts/live-deploy/siem-run` |
| `siem-net-run COMMAND`: the same pattern for the `dev_network` config. Token from `$SIEM_NET_CONFIG_DIR/token` (default `$HOME/.config/doppler-siem-net`); refuses a missing, symlinked, group or world accessible or foreign-owned token file and a folder others can write (exit 2); `#!/bin/bash -p`, fixed `PATH`, token passed to `doppler run` by `exec` only | `scripts/siem-net-run` (issue #177), `docs/owner-runbook.md` step 0b.5 |
| The runbook creates that directory mode 700 and the token file mode 600, reads the token from stdin so it is not in history, and gives a rollback (remove the directory, revoke the token) | `docs/live-deploy-runbook.md` section 2 |
| The live compose restart for Grafana runs under `doppler run --project homelab --config DEV_CONFIG`, because compose needs the webhook secret at start, which means a second copy of that one secret in that config | `docs/live-deploy-runbook.md` (around line 358), `docs/owner-runbook.md` (around line 124) |
| n8n credentials (Header Auth, Pushover) are created by `n8n-setup-alert-router.py --credentials`, sent over stdin to `n8n import:credentials` in the container; n8n encrypts them in its own volume with its own key. The script never prints a value and refuses to run if a value is missing | `scripts/live-deploy/n8n-setup-alert-router.py`, `docs/live-deploy-runbook.md` section 3 |
| n8n container variables (`EXPIRY_WATCH_ROUTER_SECRET`, `HEARTBEAT_PING_URL`) are read from the n8n container's own environment, not this compose file | `.env.example`, `docs/heartbeat.md`, `docs/expiry-watch.md` |
| `expiry_watch.py` takes secrets only from environment variables whose NAMES are in its config (`token_env`, `username_env`, `password_env`); it never reads a secret from a file and never prints one | `scripts/expiry_watch.py`, `docs/expiry-watch.md` |
| Grafana provisioning interpolates `$VARIABLE` from the Grafana container environment, so a secret never sits in a provisioning file | `docker/grafana/provisioning/alerting/contact-points.yml` |
| The JumpCloud bridge (separate repo) resolves its key from the secret manager first, then env vars | `README.md` line 616, `docs/roadmap.md` Phase 1B |
| The roadmap lists a Doppler migration (Phase 1B, issue #4) with a "`doppler run -- docker compose up`" item unchecked | `docs/roadmap.md` line 399 to 447, `README.md` line 612 to 616 |
| CI uses a Doppler identity for the security workflow | `.github/workflows/security.yml` lines 32 to 34 |
| `docs/container-engine.md`, named in the brief as prior art, does not exist at this commit. The container-engine design is `docs/design/podman.md`, which states no new secret is introduced and keeps the "secrets on stdin" pattern for `docker exec` | `docs/design/podman.md` (items 223, 328) |

Summary: the stack has ONE contract, "secrets are variables in the environment of
the process that runs compose or the script". `.env` and the secret manager are
two ways to fill that environment. The host store is not supported today.

## 3. Vendor facts (read 2026-11-19)

Secret manager (Doppler):

- `doppler run` injects secrets as environment variables. The guide warns that
  variable names such as `LD_PRELOAD` or `NODE_OPTIONS` can change how the child
  behaves, "in the worst case" leading to remote code execution, and recommends
  mounting to an ephemeral file as the alternative. VERIFIED,
  https://docs.doppler.com/docs/accessing-secrets, 2026-11-19.
- `doppler run --mount NAME` exposes secrets as a Linux named pipe removed when
  the process exits; `--mount-format`, `--mount-template`, `--mount-max-reads N`
  exist. The guide advises against saving plaintext secrets to disk and shows
  process substitution for `--env-file`. VERIFIED, same page.
- A service token is read-only by default, scoped to ONE config of ONE project,
  and read/write is an explicit opt-in. Token passing options: persisted with
  `doppler configure set token --scope DIR`, the `DOPPLER_TOKEN` variable, or
  `--token` (shell history risk). Doppler warns against CLI or personal tokens
  in live environments because they carry the creator's write access. VERIFIED,
  https://docs.doppler.com/docs/service-tokens, 2026-11-19.
- Compose passes a variable into a container only if the service lists it under
  `environment:`; Doppler documents `doppler run -- docker-compose up`.
  VERIFIED, https://docs.doppler.com/docs/docker-compose, 2026-11-19.
- The `--fallback-readonly` flag used by `siem-run` is not described on any page
  read here. The pages did not cover `--fallback`, `--fallback-readonly` or
  `--fallback-only`. UNVERIFIED against vendor docs; its use in the repo is
  VERIFIED, its exact semantics are not. Check `doppler run --help` in the
  implementation step.

Host store (systemd credentials):

- Services receive credentials as regular files in a directory named by
  `$CREDENTIALS_DIRECTORY`; sources include files, literals, sockets.
  Access is limited to the service user, not inherited by child processes, kept
  in non-swappable memory where permitted, up to 1M per service.
  `SetCredential=` values are world-readable through unit files and must not
  hold secrets. VERIFIED, https://systemd.io/CREDENTIALS/, 2026-11-19.
- `systemd-creds encrypt` uses AES256-GCM with a key from the TPM2 and/or
  `/var/lib/systemd/credential.secret`; the result goes to a file used with
  `LoadCredentialEncrypted=`. A credential encrypted on one machine cannot be
  decrypted on another. VERIFIED, same page.
- `LoadCredential=ID:PATH`: data accessible only to the unit's user (and root),
  read-only, in non-swappable memory where possible, location exported as
  `$CREDENTIALS_DIRECTORY`. `EnvironmentFile=` must be an absolute path in
  UTF-8 and a missing file stops the service unless prefixed with `-`. VERIFIED,
  https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html,
  2026-11-19 (first 200000 characters; `LoadCredentialEncrypted=` text was in the
  unread tail, so its exact wording is INFERRED from the credentials page).
- Podman: `podman secret create NAME FILE|-` reads a file or stdin; `--secret`
  accepts `mode`, `uid`, `gid`. Search result summary only (a 2026 blog and the
  man page index, not fetched): for file-based Compose secrets the host mode is
  not remapped. INFERRED. Source lead: https://docs.podman.io/en/v5.8.2/markdown/podman-secret-create.1.html
  (not read).

Searches run (for not-found items):
`query: Doppler CLI doppler run --mount secrets file service token least privilege`;
`query: podman secret create docker compose secrets file env_file permissions`.
Not found on any page read: Doppler `--fallback-readonly` semantics, and the
Docker Compose precedence of shell environment over `.env` (stated in Compose
docs but not fetched here; INFERRED, to be checked with `docker compose config`
in the test plan).

## 4. Options

The stack consumes environment variables, so a source is "a way to fill the
environment of one process, safely". Three sources, one contract.

### Option A: three first-class sources behind one launcher (recommended)

A single launcher (a generalized `siem-run`, shipped under `scripts/`) selects a
source by one setting, `SIEM_SECRETS_SOURCE`, and then `exec`s the command with
the secrets in ITS environment only:

| Source value | What the launcher does | Where the secret lives at rest |
|---|---|---|
| `doppler` | today's `siem-run`: token file mode 600 in a private dir, `doppler run` | The secret manager; only a read-only token on the host |
| `envfile` | reads a mode-600 file by a SAFE parser (not `source`), exports the names, `exec` | `.env` on the host, mode 600, owner the deploy user |
| `credstore` | reads files from `$CREDENTIALS_DIRECTORY` (systemd `LoadCredential=` or `LoadCredentialEncrypted=`), one file per variable name, exports them, `exec` | systemd credential files, root-owned mode 600 or encrypted with `systemd-creds` |

Trade-offs:

- Pro: every script and `docker compose` run is wrapped the same way; the
  contract stays "environment". No change to compose interpolation.
- Pro: `.env` stays the default for a first-time deployer; nothing is lost.
- Con: three code paths to test. The launcher is small and each path is covered
  by the same start-up test (section 8).
- Con: for `credstore`, a compose run started by hand has no
  `$CREDENTIALS_DIRECTORY`; the supported way is a systemd unit (a oneshot or
  the Quadlet/podman units from `docs/design/podman.md`). INFERRED.

### Option B: `.env` only, with Doppler as a way to write it

`doppler secrets download --format env` to `.env`. Rejected as the primary path:
the vendor advises against plaintext secrets on disk
(https://docs.doppler.com/docs/accessing-secrets, 2026-11-19), and it turns a
read-only token setup into a long-lived plaintext file.

### Option C: Compose `secrets:` / `podman secret` for every value

Moves each secret to a file mounted into the container. Rejected for now: most
images here read environment variables (the compose file interpolates them),
so each service would need `_FILE` support or a wrapper. Large change, per-image
research. Keep as a later hardening epic. INFERRED from `docker/docker-compose.yml`.

Recommendation: **Option A**, delivered in this order: envfile (safe parser and
`check-env` for the env case), doppler (generalize `siem-run`), credstore.

## 5. Security

Where secret values may live:

- A secret manager, the process environment of the one command, a mode-600
  file owned by the deploy user, or a systemd credential. Never in git, in
  `argv`, in a unit file `Environment=` or `SetCredential=` line, in logs, in
  CI output, in an issue or a PR.
- The secret-manager token on the host is the one long-lived credential: read-only,
  one project and config, in a mode-600 file inside a mode-700 directory (as
  `docs/live-deploy-runbook.md` section 2 does). Create it with the shortest
  useful `--max-age` where the deployment allows rotation (Doppler documents
  `doppler configs tokens create ... --max-age`, services-tokens page,
  2026-11-19).
- New secrets go to the dev environment/config first (owner rule; the runbook
  already uses `dev_network`). Production configs only after the owner says the
  deployment is live.

File modes and ownership:

| Path | Mode | Owner | Notes |
|---|---|---|---|
| Config directory with the token | 700 | deploy user | existing runbook |
| Token file | 600 | deploy user | existing runbook |
| `.env` | 600 | deploy user | README says 600; the launcher should REFUSE to read a file that is group or world readable, or a symlink (the check-env pattern) |
| Credential source files for systemd | 600 | root | read by systemd; the service sees them at `$CREDENTIALS_DIRECTORY` |
| Encrypted credential files | 600 | root | decryptable on the same machine only |

Existing hardening rules that must carry over (VERIFIED, paths above):

1. Never print a value; messages name the variable (`lib-secrets.sh`,
   `check-env.sh`, the n8n setup script).
2. One placeholder rule, in `lib-secrets.sh`, with the Python twin.
3. `check-env.sh` opens once, compares inode, refuses symlinks and control bytes.
4. Secrets travel on stdin or in a child environment, never `argv`
   (`n8n-setup-alert-router.py`, `docs/design/podman.md` item 223).
5. `source .env` runs the file as shell. The launcher must parse `NAME=VALUE`
   lines itself (names matching `[A-Za-z_][A-Za-z0-9_]*`, no command
   substitution) and refuse names the loader treats as code-loading
   (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `NODE_OPTIONS`, `PATH`, and the like). The
   same risk is documented by the vendor for injected names. The existing scripts
   that `source` the file should call the launcher instead. This is a hardening
   change, tracked in the implementation issue.
6. Environment variables are visible to the process and its children, and in
   `docker inspect` of a container that receives them. The credentials page says
   `systemd` credentials are not inherited by children. For the stack this means
   the `credstore` source still ends up as environment inside the compose
   process; its gain is at-rest protection and per-service scoping, not an end of
   environment exposure. INFERRED consequence; state it in the user docs.
7. Scrub: process listing and `docker compose config` output contain values when
   interpolated. Docs must say never to run `docker compose config` into a log or
   CI artifact. INFERRED (Compose behavior).

Least privilege per source (what each doc must state):

- Secret manager: read-only service token, one config; no personal or CLI token
  on a server; revoke on host retirement.
- Env file: only the deploy user reads it; no backup of it to a world-readable
  place; the backup tool `backup-state.py` already takes care to exclude
  secrets (not re-verified here; check in the implementation).
- Host store: units that need a credential name only that credential
  (`LoadCredential=ID:PATH` per unit), nothing shared.

## 6. Migration plan and owner decisions

1. This design merges (docs only).
2. Implementation issue A: safe env parser and launcher, `envfile` source,
   refusal rules, tests. Replace the `source "$envf"` blocks in scripts 04, 05,
   08, 10, 11 and `08b` with a call to the launcher. No behavior change for a
   deployer who exports variables.
3. Issue B: generalize `siem-run` into the launcher's `doppler` source (same
   token file, same directory, same mode checks); keep the name `siem-run` as the
   entry point so the runbook commands still work.
4. Issue C: `credstore` source and a documented unit file example; add a
   start-up test.
5. Docs: one "Secret sources" page with the least-privilege setup of each
   (the done-when of #117), README link, `.env.example` text updated.
6. Owner-only steps (listed, not done): creating or rotating any service token;
   choosing the dev config name; revoking tokens; any change on the live host.

Owner decisions (recommended first):

- D1. Make the launcher the single entry point for scripts and compose.
  Recommended yes. Alternative: keep per-script `.env` loading.
- D2. Keep `change-passwords.sh` writing `.env` only for the `envfile` source,
  and for the other sources print "set the new value in your source" and stop.
  Recommended yes.
- D3. `credstore` ships in the first release or later. Recommended later (after
  envfile and doppler), because the Quadlet units come with the podman work.

## 7. Open questions (recommended answer first)

1. Should the live stack move from `doppler run` for compose to a rendered,
   mount-based file? Recommended: no, keep environment injection; revisit with
   `--mount` and `--mount-max-reads 1` only if a command reads a file once.
2. Does the second copy of `GRAFANA_WEBHOOK_SECRET` in the dev config go away?
   Recommended: yes, once the router is optional (see optional-components.md)
   because compose will stop requiring it when the router is off.
3. Is `--fallback-readonly` wanted? Recommended: keep until its semantics are
   read in `doppler run --help` and recorded; it is VERIFIED in use but not in
   vendor docs.
4. Should `check-env.sh` accept a variable set only in the environment?
   Recommended: yes, add `--env` mode that checks the process environment by the
   same rule; the file mode stays as is.
5. Which platforms for `credstore`? Recommended: Linux with systemd only;
   state that macOS or containers-in-CI use the other two.

## 8. Test plan

Tests that would prove the claim "the stack starts from each source":

1. Unit (pure shell/Python, no docker): launcher with `envfile` exports exactly
   the names in a fixture file; refuses a symlink, a mode 644 file, a name
   `LD_PRELOAD`, a line with `$(...)`, a CRLF file; never prints a value (grep
   the combined output for a canary value, as the existing tests do).
2. Unit: launcher with `doppler` source and a stub `doppler` on `PATH` receives
   the token only through `DOPPLER_TOKEN`; `argv` of the stub never contains it
   (assert on recorded `argv`); missing token file exits 2.
3. Unit: `credstore` with a fake `$CREDENTIALS_DIRECTORY` of mode 600 files maps
   file names to variables; empty file and placeholder rejected through
   `secret_is_placeholder`.
4. Parity: `tests/python/test_required_secrets.py` style check that all three
   sources use the one placeholder rule.
5. Compose: `docker compose config` with the CI env (`tests/compose.ci.env`)
   injected through the launcher gives the same resolved config as through `.env`
   (compare hashes of the config with canary values, never print it). This also
   settles the Compose precedence question in section 3.
6. Revert-proof: each refusal test fails when the matching guard is removed.
7. Manual (owner or live host, listed not run): start the stack once per source
   on a rehearsal host and run `scripts/05-verify.sh`.
