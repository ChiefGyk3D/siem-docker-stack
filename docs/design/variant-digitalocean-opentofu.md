# Design: Digital Ocean variant, an OpenTofu module for droplet, firewall and volume

Status: DRAFT for the owner's decision. Docs only: no code, no configuration,
no live change, no account touched. Tracked in issue #114 (epic #62), child of
the deployment variants epic #111. Companion design:
[telemetry-sink.md](telemetry-sink.md).

Marking: **VERIFIED** means read from a file in this repository at master
7c8de1b (path given) or from a vendor page (URL, read 2026-11-19).
**INFERRED** means reasoned from those and not tested; each INFERRED item needs
a test on a throwaway account before it is relied on. Examples use
`example.com` and placeholder names only. No hostname, address, account
identifier or secret value appears here.

## 1. Problem

Issue #114: an OpenTofu (Terraform compatible) module that creates the droplet,
firewall and volume and installs the stack. Secret values come from the secret
manager and never from the repository. Plan before apply, a destroy path and a
cost note. Done when a fresh account can plan and apply it.

## 2. Goals and non-goals

Goals

1. One module, one `tofu apply`, a droplet running the existing stack through
   the repo's own scripts, with data on a separate block volume.
2. Default posture is closed: no public inbound port, management over a
   private overlay.
3. No secret in code, in the module's variables files, or (as far as the
   provider allows) in state.
4. Every size, region and CIDR is an input; nothing is tied to the
   maintainer's hardware, hosts or addresses.
5. A plan that runs in CI with no credentials.

Non-goals

- Not a managed service: no Kubernetes, no managed database, no load balancer.
- Not high availability: one droplet, one volume.
- Not the telemetry sink choice (see [telemetry-sink.md](telemetry-sink.md)).
- Not a change to the compose files or scripts. Where the module needs a
  script to be non-interactive, that is a follow-up issue, listed in section 14.
- No assumption about any Spacelift account (section 9).

## 3. What the stack needs from the host (VERIFIED, master 7c8de1b)

| Fact | Source |
|---|---|
| One compose project, bridge network `siem-net`; 16 always-on services plus two profile services (crowdsec, portainer) | `docker/docker-compose.yml` |
| Persistent data is bind mounts under `/data/hot` and `/data/warm` (OpenSearch, InfluxDB, Prometheus, Grafana, Wazuh) | `docker/docker-compose.yml`, `docs/disk-strategy.md` |
| The design assumes two disk tiers (NVMe hot, SATA warm), prepared by `01-disk-setup.sh` | `docs/disk-strategy.md`, `scripts/01-disk-setup.sh` |
| Bootstrap runs as root on Debian or Ubuntu (`apt`), tunes sysctl (`vm.max_map_count=262144`), installs docker-ce and the compose plugin, sets ufw, creates `/opt/siem` | `scripts/02-bootstrap.sh` |
| Deploy copies a validated `.env` into the deploy directory; no `.env`, exit 1 | `scripts/03-deploy.sh` lines 116 to 133 |
| Host ports bind to `BIND_ADDR` and `INGEST_BIND_ADDR`, default loopback | `docker/docker-compose.yml` |
| Ports that bind below 1024: 514 (syslog-ng) and 443 (Wazuh dashboard) | `docker/docker-compose.yml` |
| Docker-published ports bypass ufw (the bootstrap says so), so host ufw is not a sufficient control | `scripts/02-bootstrap.sh` |
| Reference hardware 64 GB RAM; stated minimum 16 GB RAM, 2 cores, 100 GB SSD plus a second disk | `README.md` lines 70 to 93 |
| Secrets are interpolated from `.env` or the process environment, with `${VAR:?msg}` on each required one; `check-env.sh` validates a `.env` file | `docker/docker-compose.yml`, `scripts/check-env.sh`, `docs/design/secrets-sources.md` |

Consequence (INFERRED): a droplet has one root disk plus block volumes. The hot
and warm tiers can be two directories on one volume, or two volumes. Section
4 recommends one volume first.

## 4. Resources the module creates

Provider documentation (all read 2026-11-19 from the provider's GitHub docs,
because the registry pages render only a title through the fetch tool):

- [P] https://raw.githubusercontent.com/digitalocean/terraform-provider-digitalocean/main/docs/index.md
- [D] .../docs/resources/droplet.md
- [F] .../docs/resources/firewall.md
- [V] .../docs/resources/volume.md and .../docs/resources/volume_attachment.md
- [FW] https://docs.digitalocean.com/products/networking/firewalls/
- [S] https://docs.digitalocean.com/reference/api/scopes/
- [PR] https://www.digitalocean.com/pricing/droplets and
  https://docs.digitalocean.com/products/volumes/details/pricing/
- [VL] https://docs.digitalocean.com/products/volumes/details/limits/
- [UD] https://docs.digitalocean.com/products/droplets/details/limits/ (silent
  on user data size; see the note under the droplet row)

| Resource | Purpose | Notes (VERIFIED from the source in brackets) |
|---|---|---|
| `digitalocean_vpc` | Private network for the droplet | The droplet takes `vpc_uuid`; omitted means the region's default VPC [D]. A dedicated VPC is recommended (INFERRED: it keeps the stack off the default VPC where other resources may live). Scopes `vpc:*` exist [S]. |
| `digitalocean_ssh_key` (optional) | Public key for break-glass access | Droplet `ssh_keys` takes IDs or fingerprints; keys cannot be added or removed after creation and changing the list recreates the droplet [D]. So the module takes an existing key fingerprint by default and creates a key only when a public key is supplied. A public key is not a secret. |
| `digitalocean_droplet` | The host | Required: `image`, `name`, `size`; `region` is documented without "required" [D]. `user_data` change forces a new droplet [D]. `monitoring` and `backups` default false, `ipv6` cannot be disabled once enabled, `resize_disk` defaults true and a disk increase is permanent [D]. Exports `ipv4_address`, `ipv4_address_private`, `price_monthly`, `vcpus`, `disk`, `volume_ids` [D]. The 64 KiB `user_data` cap is INFERRED from search results quoting the API reference, not read on an official page; the bootstrap payload must stay small (section 8). |
| `digitalocean_volume` | Data volume (`/data`) | Required `region`, `name`, `size` in GiB; `initial_filesystem_type` xfs or ext4; `size` can only be expanded; `snapshot_id` creates from a snapshot [V]. Up to 15 volumes per droplet, 1 GiB to 16 TiB for Standard [VL]. Billed whether or not attached [PR]. |
| `digitalocean_volume_attachment` | Attach the volume | Do not mix with the droplet's `volume_ids`: both together show constant drift [D][V]. Module uses the attachment resource only. Attach needs `block_storage_action:create` as well [S]. |
| `digitalocean_firewall` | Cloud firewall | Stateful, blocks everything not expressly permitted, applies by droplet name or tag [FW]. `tags` max 5, `droplet_ids` max 10; rule `protocol`, `port_range`, `source_addresses`, `source_tags`, `action` [F]. The module attaches by tag, so a rebuilt droplet is covered at once (INFERRED benefit). |
| `digitalocean_tag` (optional) | Tags | Droplet, firewall and volume all take `tags` [D][F][V]. There is no `tag:update` scope, so tags are created, not edited [S]. |

Deliberately not created: reserved IP, load balancer, DNS records, Spaces
bucket, project. Each is an optional follow-up. A public DNS name is the
maintainer's choice and uses `example.com` in examples only.

### 4.1 Volume layout decision

Recommended: one volume mounted at `/data`, with `hot` and `warm` as
directories, because the stack only needs the paths `/data/hot` and
`/data/warm` (VERIFIED: bind mounts in `docker/docker-compose.yml`). The cost
is losing the physical hot to warm move that `docs/disk-strategy.md` explains
(the ISM policy still runs; both tiers are on the same storage). Alternative:
two volumes, `hot` and `warm`. Digital Ocean sells a High Performance volume
only in preview with a 128 GiB minimum [VL][PR]; whether it matches the "NVMe
hot" role is INFERRED and not measured. Owner decision O3.

## 5. Inputs and outputs (names only)

Inputs (all variables, no defaults for the secret-bearing ones; there are
none that hold a secret value, see section 6):

| Name | Meaning | Default idea |
|---|---|---|
| `name_prefix` | Prefix for every resource name | `siem` |
| `region` | Region slug | none (required) |
| `droplet_size` | Size slug | none (required; section 11 gives reference sizes) |
| `droplet_image` | Image slug | a current Ubuntu LTS slug (INFERRED supported by the bootstrap, which uses `apt`; not tested) |
| `volume_size_gib` | Data volume size | none (required) |
| `volume_filesystem` | `xfs` or `ext4` | `xfs` |
| `ssh_key_fingerprints` | Existing key fingerprints | `[]` |
| `ssh_public_keys` | Public keys to create | `[]` |
| `vpc_cidr` | Dedicated VPC range | a private range, overridable |
| `admin_source_cidrs` | CIDRs allowed to SSH | `[]` (empty means no public SSH) |
| `extra_inbound_rules` | Optional extra rules (list of objects) | `[]` |
| `overlay_connector_enabled` | Install a private overlay connector in cloud-init | `false` |
| `enable_backups` | Droplet backups | `false` |
| `repo_ref` | Git ref of this repo to deploy, a commit or tag | none (required, pinned) |
| `secrets_source` | `doppler`, `env-file`, `host` (names from the secrets design) | `doppler` |
| `telemetry_sink` | Value passed through to the stack (see telemetry design) | `self-hosted` |
| `tags` | Extra tags | `[]` |
| `monthly_cost_ceiling_usd` | Plan-time guard (section 11) | none (required) |

Outputs:

| Name | Meaning |
|---|---|
| `droplet_id`, `droplet_urn` | Identifiers for tagging and teardown checks |
| `droplet_ipv4_private` | For the private overlay and operator use |
| `droplet_ipv4_public` | Present only so the operator knows what the firewall protects; sensitive-false |
| `volume_id` | For snapshot and restore steps |
| `firewall_id` | For audit |
| `estimated_monthly_cost_usd` | Sum of droplet `price_monthly` and volume GiB times the volume rate |
| `bootstrap_status_hint` | Text telling the operator the exact verification command to run (section 12) |

There is no output that contains a secret. INFERRED: provider outputs that
echo `user_data` must be avoided, since user data lands in state (section 6).

## 6. Secret handling

### 6.1 What is a secret here

1. The provider token (Digital Ocean personal access token).
2. The state backend credentials, if state is remote (section 8).
3. The stack's own secrets (the `.env` list in `README.md`: OpenSearch,
   Grafana, Influx, Wazuh, webhook secrets and more).
4. The telemetry sink credentials (see telemetry design).

### 6.2 Provider token

- VERIFIED [P]: the provider reads `DIGITALOCEAN_TOKEN`, then
  `DIGITALOCEAN_ACCESS_TOKEN`, when the `token` argument is omitted. The module
  therefore declares the provider with no token argument and no token variable.
  The page shows a `do_token` variable fed from tfvars or `-var`; that path puts
  the value in a file or in argv, so it is rejected here (INFERRED risk,
  matches the owner rule that secrets are env var or secret manager, never repo,
  argv or logs).
- Where it lives: the secret manager (the project and config are the owner's
  choice, named in the plan, dev before prd), injected as an environment
  variable for the one command only.
- VERIFIED [S]: custom scopes exist. Minimum set for this module:
  `droplet:create|read|update|delete`, `firewall:create|read|update|delete`,
  `block_storage:create|read|update|delete`, `block_storage_action:create`,
  `ssh_key:create|read|update|delete` (only if the module creates a key),
  `vpc:create|read|update|delete`, `tag:create|read|delete`. The page lists no
  `tag:update`. Scope names are VERIFIED; whether the provider also calls
  endpoints outside that list (for example `actions`, `image:read`, `regions`
  or `sizes` reads) is INFERRED and must be proven by a throwaway-account plan
  and apply with exactly these scopes. The token must never be a full-access
  token; if the provider needs an additional read scope, it is added by name
  after the failure is observed, not guessed.
- Two tokens, by purpose and tier: a plan token with read scopes only
  (CI or Spacelift-style plan) and an apply token with write scopes (the
  operator). INFERRED: read-only scopes suffice for `tofu plan`; a refresh
  reads only. Verify on the throwaway account.
- Rotation: expiry is a Digital Ocean token option (INFERRED, not read on a
  page in this pass); the owner's standard is a rotated a/b pair in the secret
  manager (memory `feedback-cloudflare-tokens-always-doppler-rotated` applies
  the same pattern to Cloudflare; whether it extends to Digital Ocean is owner
  decision O7). Rotation never needs a state change, because the token is not
  in state.

### 6.3 State and `user_data`

VERIFIED: OpenTofu says state can contain secrets, and offers state and plan
encryption with PBKDF2 or a KMS key provider and AES-GCM
(https://opentofu.org/docs/language/state/encryption/, 2026-11-19).
`user_data` is a plain string argument of the droplet [D], so INFERRED: anything
placed there is stored in state in clear text, and DO stores it with the
droplet. Therefore the module's rule is: `user_data` carries no secret.

Design for the stack's secrets: cloud-init installs the secret manager CLI (or
the host store) and an access identity that is NOT in `user_data` text. How the
first credential reaches the droplet without being in state or `user_data` is
the one hard problem of this variant; the options:

| Option | How | Verdict |
|---|---|---|
| A. Operator pushes the bootstrap credential over the private overlay after first boot | One command from the operator's workstation, secret read from the secret manager, never in state | Recommended (INFERRED: works because nothing secret is in the droplet at creation) |
| B. Secret in `user_data` | Simple | Rejected: lands in state and in the droplet record |
| C. Short-lived, single-use token in `user_data` that the droplet exchanges for the real one | Reduces exposure | Possible later; depends on secret manager support (INFERRED, unverified); owner decision O6 |

With option A the first apply yields a droplet that is up, firewalled and
bootstrapped with packages and repo checkout but with the stack stopped until
the operator delivers secrets. The module output `bootstrap_status_hint` says
exactly that. This also fits the repo's `03-deploy.sh`, which copies a
validated `.env` itself (VERIFIED, lines 116 to 133).

Mitigations in addition: mark every module variable that could hold a secret as
sensitive (there should be none); enable state encryption with a key from a
KMS or a passphrase from the secret manager; never run with `TF_LOG` set above
info in shared logs (INFERRED: debug logs can include API payloads; unverified).

## 7. Network posture

Default rule set, expressed as the firewall resource design:

| Direction | Rule | Default |
|---|---|---|
| Inbound | None from the public internet | closed |
| Inbound | TCP 22 from `admin_source_cidrs` | only when the list is non-empty |
| Inbound | From the private overlay connector's source | none needed: the overlay connector dials out (INFERRED, see below) |
| Outbound | TCP 443 and 80 (packages, container images, repo, secret manager API, telemetry sink) | allow |
| Outbound | UDP and TCP 53, UDP 123 | allow |
| Outbound | Everything else | not permitted (cloud firewall blocks unmatched, VERIFIED [FW] for inbound; the outbound default is not stated on the page read, INFERRED) |

Why nothing is public: the compose stack binds every UI and API to loopback by
default (VERIFIED, `docker/docker-compose.yml`), so the stack itself needs no
public port to run. The only ports the stack "truly needs" from outside are
those of the log sources the deployer chooses: syslog 514, Beats 5044,
Wazuh agent 1514 and 1515, Prometheus OTLP 9091. Those are an owner decision
per deployer (O4). Recommendation: do not open them in the module; a deployer
who needs them adds `extra_inbound_rules` with a narrow source CIDR, and the
stack's own authentication stays on (VERIFIED: `docs/prometheus-otlp.md` gives
the OTLP port authenticated TLS).

Docker bypasses host ufw for published ports (VERIFIED, `scripts/02-bootstrap.sh`).
That is the reason the control is the cloud firewall, which sits outside the
host (INFERRED, reasonable; the cloud firewall is a network service [FW]). Both
layers stay: ufw as defense in depth, the cloud firewall as the control.

Management over a private overlay such as the owner's Twingate: the connector
runs on the droplet and dials out; operators reach SSH and the UIs on the
droplet's private address through the overlay. INFERRED, not tested here: the
connector needs a credential at install time, which makes it a secret, so it
follows option A of section 6.3 (delivered by the operator, not in
`user_data`). `overlay_connector_enabled` is false by default, so a deployer
without that product uses `admin_source_cidrs`, which the recommended default
leaves empty and so no SSH is reachable until the operator picks one of the
two. Owner decision O5 (what the overlay looks like for other deployers).

The firewall's private-VPC filtering is not stated on the page read [FW]; do
not rely on it for east-west rules (single droplet, not needed).

## 8. Bootstrap (cloud-init) with the repo's scripts

Design: `user_data` is a short cloud-config that does only: set the hostname
from `name_prefix`, install `git`, check out `repo_ref` into `/opt/siem-src`
(a commit or tag; a branch name is rejected by a variable validation), format
and mount the volume at `/data` by its stable device path, create `/data/hot`
and `/data/warm`, and run the repo's own scripts in order.

Script fit (INFERRED from script headers and names; the scripts were not run):

| Step | Script | Fit |
|---|---|---|
| Disks | `01-disk-setup.sh` | Built for physical disks (gdisk is installed by `02`). On a droplet the module formats and mounts the volume itself and skips this script. A follow-up flag may be needed (issue to file, section 14). |
| Host | `02-bootstrap.sh` | Needs root; uses `apt`; installs Docker; sets ufw; takes `SIEM_USER`. Runs under cloud-init as root. INFERRED: `apt upgrade -y` runs unattended. |
| Secrets, deploy | `03-deploy.sh` | Waits for the operator's secret delivery (section 6.3). |
| Verify | `05-verify.sh` | Run by the operator as the end-to-end check (section 12). |

The `user_data` stays small (INFERRED 64 KiB cap, section 4) because it holds
only the checkout and the script calls; no repo content is embedded.

Supply chain note (INFERRED): a pinned `repo_ref` makes the droplet
reproducible; any dependency pinning stays as in the repo (owner rule: pin and
hold new releases seven days).

## 9. State storage and the plan and apply flow

State options:

| Option | Notes |
|---|---|
| Local state | Fine for a rehearsal on a throwaway account. State holds `user_data` and the droplet record, so the file is protected like a secret (INFERRED). |
| S3-compatible remote state on a Digital Ocean Spaces bucket | VERIFIED backend settings: custom endpoint, `use_path_style`, region still required, several `skip_*` flags for non-AWS stores, `use_lockfile` as the preferred lock, `tofu init -reconfigure` after a change (https://opentofu.org/docs/language/settings/backends/s3/, 2026-11-19). NOT VERIFIED: whether Spaces supports the conditional writes that `use_lockfile` relies on; the page says to verify with the provider. Spaces needs its own key pair, which is a second secret (state backend credentials, section 6.1). Adds a Spaces cost. |
| A managed runner such as Spacelift | Read-only mention only: a deployment option. A stack there would hold the token and state, run the same module, and add plan policy and approval. No assumption is made about the owner's account, its spaces, its worker pools or its integrations. Nothing in this design requires it. |

Flow, the same for every option:

1. `tofu init` (backend, providers; providers pinned by version and lock file).
2. `tofu validate`, `tofu fmt -check` (no credentials).
3. `tofu plan -out` with the plan token; the saved plan is encrypted when state
   encryption is configured (VERIFIED: encryption covers plan files).
4. A human reads the plan, in particular `estimated_monthly_cost_usd`.
5. `tofu apply` of that exact plan with the apply token.
6. Operator delivers secrets (6.3), runs `03-deploy.sh` and `05-verify.sh`.

## 10. Test plan

| Layer | What | Credentials | Evidence |
|---|---|---|---|
| Static | `tofu fmt -check`, `tofu validate`, a secret scan on the module directory | none | exit codes in CI |
| Variable validation | A `tofu test` file with `command = plan`: bad `repo_ref` (a branch name), empty `region`, cost ceiling exceeded, expect failure | none | VERIFIED: `tofu test` supports `command = plan`, `mock_provider`, `override_resource` (https://opentofu.org/docs/cli/commands/test/, 2026-11-19) |
| Mocked plan | A `mock_provider "digitalocean"` run that asserts: firewall has no inbound rule from `0.0.0.0/0` by default, tags present on droplet, firewall and volume, no `volume_ids` on the droplet, `user_data` contains no value from a secret-shaped regex | none | The page says mocks skip real provider calls and generate computed values. Whether this provider needs a token at provider-configure time under a mock is not stated: INFERRED yes it does not; verify |
| Real plan, no apply | `tofu plan` with a read-only token on a throwaway account | read token | plan output in the PR |
| Rehearsal apply and destroy | Full cycle on a throwaway account, then `05-verify.sh`, then destroy; compare resource list before and after | write token | before and after listings |

CI shape (INFERRED, follows the owner's rule): a caller of the GYST `tofu-ci`
workflow, gate named `CI green`, with the mock-provider test as the
credential-free job. The rehearsal apply is a manual, labelled job, never run on
pull requests from forks.

Do not exercise: any live account, any account the owner has not named, the
maintainer's production Doppler config (dev before prd).

## 11. Cost bounds and tagging

VERIFIED prices (https://www.digitalocean.com/pricing/droplets and
https://docs.digitalocean.com/products/volumes/details/pricing/, 2026-11-19):

| Sizing | Slug | Monthly |
|---|---|---|
| Basic shared, 8 vCPU, 16 GiB | `s-8vcpu-16gb` | $96.00 |
| General Purpose, 4 vCPU, 16 GiB | `g-4vcpu-16gb` | $126.00 |
| General Purpose, 8 vCPU, 32 GiB | `g-8vcpu-32gb` | $252.00 |
| CPU-Optimized, 8 vCPU, 16 GiB | `c-8` | $168.00 |
| Standard volume | n/a | $0.10 per GiB per month, billed while it exists, attached or not |

Billing model (VERIFIED, https://docs.digitalocean.com/products/droplets/details/pricing/):
per second, usage capped at 672 hours a month, and a powered-off droplet is
still billed; only destroying it stops the charge.

Reference estimate (arithmetic on the rows above; INFERRED sizing): the repo's
stated minimum is 16 GiB RAM (VERIFIED, `README.md` line 93) so a 16 GiB
droplet plus a 500 GiB volume is about $96 + $50 = $146 a month on the Basic
row, $176 on the General Purpose row. Bandwidth overage was not found on the
pages read: UNVERIFIED, owner may want a check before relying on the figures.
Whether a Basic shared droplet is adequate for OpenSearch (JVM heap 12 GB in
the 64 GB reference, `README.md` memory budget) is INFERRED and needs a test.

Bounds in the module:

1. A variable validation that rejects a size not on an allow list (the list is
   a module input with a default of the rows above).
2. `monthly_cost_ceiling_usd`: a precondition comparing the sum of the
   droplet's `price_monthly` and the volume's GiB times the rate against the
   ceiling (INFERRED: the price attributes are exported by the droplet [D],
   so the check can only run after the droplet resource is known, meaning the
   gate fails at apply, not plan; the plan output still shows the number. A
   data source for sizes may allow a plan-time check; unverified).
3. Tags on every resource: `project:siem-stack`, `managed-by:opentofu`,
   `env:<value>` and an `owner` tag. Digital Ocean tags are plain names; the
   `key:value` form is a convention (INFERRED). A tag is how the firewall
   attaches, so tag names are not decoration.
4. A reminder that backups add cost (`enable_backups` is false).

## 12. Verification (what "done" means for an apply)

Observed end to end by the operator, on the droplet over the overlay:

1. `05-verify.sh` exits 0 (VERIFIED the script exists; its exact checks are not
   restated here).
2. `docker compose ps` shows the services healthy.
3. From outside the overlay, a port scan of the public address finds no open
   port (INFERRED check; run only against the operator's own droplet).
4. The firewall resource's rule list matches the design (read through the
   provider data source or the API).

## 13. Teardown and rollback

| Case | Action |
|---|---|
| Failed apply | `tofu apply` again; the volume and firewall are independent resources so a droplet failure leaves the volume intact. |
| Replace the droplet (a `user_data` change forces replacement [D]) | The data volume survives because it is a separate resource; the module must set `prevent_destroy` on the volume (INFERRED, standard OpenTofu lifecycle, not read from a page in this pass) and the attachment re-links on the new droplet. Operator re-delivers secrets (6.3). |
| Roll back a bad stack release | Redeploy a prior `repo_ref`; stack data is on the volume. |
| Full teardown | Snapshot the volume first (the provider supports `snapshot_id` on create [V]); `tofu destroy` needs the `prevent_destroy` guard removed on purpose; read back the resource list and the billing console. A volume left behind keeps billing [PR]. |
| Resize | Droplet `resize_disk` defaults true and disk growth is permanent [D]; set it false unless growth is wanted. Volume can only grow [V]. |

## 14. Follow-up issues this design implies (to file when approved)

1. The module itself (code), under `deploy/digitalocean/` or a separate repo
   (owner decision O1).
2. A non-interactive mode for `01-disk-setup.sh` or an explicit skip flag.
3. A credential-free CI job (GYST `tofu-ci`) and the mock-provider test.
4. A rehearsal runbook on a throwaway account with the exact scopes of 6.2.
5. A verified answer to each INFERRED item that gates the apply: token
   scopes, Spaces locking, outbound default, 64 KiB `user_data` cap.

## 15. Owner decisions (recommended answer first)

| # | Decision | Recommended | Alternatives |
|---|---|---|---|
| O1 | Where the module lives | In this repo under a `deploy/` directory, versioned with the scripts it calls | Separate repo; a GYST-hosted shared module |
| O2 | State backend | Local for rehearsal, then a Spaces bucket with state encryption, lock verified first | A managed runner as a deployment option |
| O3 | Volume layout | One volume, `hot` and `warm` as directories | Two volumes |
| O4 | Public ingest ports | Closed by default, `extra_inbound_rules` per deployer | Open 514 and 1514 to named CIDRs |
| O5 | Management path | Private overlay connector (off by default) plus `admin_source_cidrs` | SSH only |
| O6 | First credential delivery | Operator pushes after boot (A) | Single-use token in `user_data` (C) |
| O7 | Token policy | Two tokens (read for plan, write for apply), scoped as in 6.2, rotated a/b in the secret manager, dev config first | One token |
| O8 | Default size | `g-4vcpu-16gb` class for a small deployment, measured before it is published as a recommendation | Basic shared |
| O9 | Throwaway account for the rehearsal | Owner names or creates it; nothing here touches an account until then | Skip the rehearsal (not recommended) |

## 16. Sources and search record

Vendor pages read 2026-11-19 are the URLs in sections 4, 9 and 11.
Web search queries used, and what they gave:

- `query: DigitalOcean droplet user data cloud-init size limit 64 KB` found
  only secondary sources for the 64 KiB cap (INFERRED).
- `query: OpenTofu test mock_provider override_resource tofu test command`
  returned third-party posts; the official page read directly confirmed the
  behavior (VERIFIED).
- Not found: the Digital Ocean bandwidth overage rate, the personal access
  token expiry options page, and an official statement of the outbound default
  for Cloud Firewalls. All stay INFERRED or UNVERIFIED above.
