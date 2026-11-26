# Updating a Twingate Connector (Docker, host networking)

How to update a Twingate Connector that runs as a Docker container with host
networking, one Connector at a time, without losing access. Placeholders:
`<connector-name>` is the container name, `<host-a>` and `<host-b>` are the
hosts that each run one Connector. Never paste a token anywhere.

Verified live on 2026-11-26 on two Connectors (the steps below worked on both).
Vendor facts were read from the Twingate docs on 2026-11-26:
<https://www.twingate.com/docs/upgrading-connectors> and
<https://twingate.com/docs/docker>.

## How these Connectors run (verified 2026-11-26)

- Image `twingate/connector:1`, a floating major tag (it moves to each new 1.x).
- One Connector per host, started with `--network host`.
- No `--sysctl`: Docker refuses a network sysctl together with host networking.
- Restart policy `unless-stopped`, command `/connectord`, no binds or mounts.
- The configuration (network, access token, refresh token, labels) lives only in
  the container's `Config.Env`. Treat that data as secret.

## Do not use the vendor upgrade script on these hosts

Twingate documents `docker-upgrade.sh` (served from
`https://binaries.twingate.com/connector/docker-upgrade.sh`; its checksum is
recorded in issue #220). Do not use the vendor upgrade script on these hosts,
for two verified reasons:

1. It finds Connectors by matching the image name in `docker ps`. Once a newer
   image has taken the `twingate/connector:1` tag, the running container shows a
   bare image ID instead of the name, so the script finds nothing.
2. It recreates the container with `--sysctl net.ipv4.ping_group_range` and
   without `--network host`. That fails on a host-networked Connector.

## Check what runs versus what is pulled

A pulled newer image does NOT mean the container is updated. The container keeps
running the image it was created from until you recreate it.

```bash
docker inspect <connector-name> --format '{{.Image}}'   # running image id
docker images                                           # images stored locally
docker exec <connector-name> ./connectord --version     # running version
```

If the image id of the running container is not the id of the newest
`twingate/connector:1` in `docker images`, the Connector is behind.

## Before you start

- Update one Connector at a time. Two Connectors per remote network keep access
  up while one restarts.
- Check the other Connector is `ALIVE` in Twingate first (for example
  `<host-b>` before you touch `<host-a>`). Admin API, read-only key:

  ```graphql
  { connectors(first: 100) { edges { node { name version state lastHeartbeatAt } } } }
  ```

- Run everything on the Connector's own host, not on a laptop.

## Procedure

```bash
umask 077
docker inspect <connector-name> > ~/connector-inspect.json
# env file from Config.Env, without PATH (needs jq)
jq -r '.[0].Config.Env[]' ~/connector-inspect.json | grep -v '^PATH=' > ~/connector.env
docker pull twingate/connector:1
docker images                       # confirm a newer image id than the running one
docker stop <connector-name>
docker rm <connector-name>
docker run -d --network host --env-file ~/connector.env \
  --name <connector-name> --restart=unless-stopped twingate/connector:1
```

Verify, then clean up:

```bash
docker ps                                            # container is Up
docker exec <connector-name> ./connectord --version  # 1.96.0 on 2026-11-26
```

Then confirm the Connector is `ALIVE` in Twingate with the Admin API query above,
and that the version matches. Only after that:

```bash
shred -u ~/connector.env ~/connector-inspect.json
```

The saved inspect file and the env file contain tokens. They must be mode 600
(the `umask 077` above does that) and are shredded after verifying. Keep the
inspect file until you have verified, in case you need a rollback.

## Rollback

The old image stays on the host until pruned, so do not prune before verifying.
Recreate from the saved inspect and env files with the old image id as the image
argument:

```bash
docker stop <connector-name> && docker rm <connector-name>
docker run -d --network host --env-file ~/connector.env \
  --name <connector-name> --restart=unless-stopped <old-image-id>
```

## Failure modes seen

- A Connector can stop cleanly (exit 0) and stay stopped under `unless-stopped`
  if it was stopped manually. Check `docker ps -a`, and the alert
  "Connector not ALIVE".
- A stale `variables.env` owned by root blocked `--env-file`. Write the env file
  yourself with the commands above, in your own home directory.
- A laptop-only command (it needs `doppler` and `jq`) was run on a host. Run only
  the commands in this page on the host.

See also [update-alerting.md](update-alerting.md) for the alerts that tell you a
Connector is behind.
