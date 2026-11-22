# Architecture

## Context

```
 Internet ── Cloudflare ──tunnel──> cloudflared ──> rest-server ──> /repos (NAS disk)
                                                                      ▲
 Browser (LAN) ──HTTPS──> BelayPoint ──restic (local backend)─────────┘
```

- The rest-server runs on a NAS as a Docker stack. Clients (StackBelay) reach
  it only through a Cloudflare tunnel; the NAS accepts no inbound connections
  from the internet.
- The rest-server runs in **append-only** mode: clients can add data but not
  delete or rewrite it. Retention therefore has to happen on the server side.
- BelayPoint runs next to it, reachable **only from the LAN**. It needs no
  network access to the rest-server: it works on the repository files directly
  with restic's local backend.
- BelayPoint is the only component that can delete backup data.

## Container

One image, one binary (`/app/belaypoint`), restic from the base image.

| Mount | Content | Mode |
|---|---|---|
| `/repos` | rest-server data directory: repositories and `.htpasswd` | read-write |
| `/config` | `vault.json`, `belaypoint.db`, `tls/`, `jobs/` (logs), `cache/` (restic cache) | read-write |

No Docker socket, no other mounts, no worker containers, no self-update.

Recommended runtime settings (see `deploy/compose.example.yml`):

- `user:` the UID/GID that owns the repository files (the same user the
  rest-server runs as). Files written by `prune` must stay readable and
  writable for the rest-server. At startup BelayPoint compares its UID/GID with
  the owner of `/repos` and logs a warning on mismatch.
- `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`,
  `tmpfs: /tmp`.
- `mem_limit` equal to `memswap_limit`, so the container cannot swap (secrets
  in memory must not end up in swap). Core dumps disabled (`ulimits: core: 0`).
- Own Docker network, **not** shared with cloudflared. The port is published
  on the NAS's LAN IPv4 address only: `192.168.1.10:8443:8443`.

### Example

```yaml
services:
  rest-server:
    image: restic/rest-server
    user: "1000:1000"
    environment:
      OPTIONS: "--append-only --private-repos"
    volumes:
      - /volume1/restic:/data
    networks: [tunnel]

  cloudflared:
    image: cloudflare/cloudflared
    command: tunnel run
    networks: [tunnel]

  belaypoint:
    image: ghcr.io/mb512/belaypoint:latest
    user: "1000:1000"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: [/tmp]
    mem_limit: 512m
    memswap_limit: 512m
    ulimits:
      core: 0
    environment:
      BELAYPOINT_LAN_ADDRESS: "192.168.1.10/24"
      BELAYPOINT_HOSTNAMES: "nas.fritz.box"
      TZ: Europe/Berlin
    volumes:
      - /volume1/restic:/repos
      - ./belaypoint:/config
    ports:
      - "192.168.1.10:8443:8443"
    networks: [admin]

networks:
  tunnel:
  admin:
```

## Configuration

| Variable | Meaning |
|---|---|
| `BELAYPOINT_LAN_ADDRESS` | LAN address of the NAS with prefix, e.g. `192.168.1.10/24`. Used as certificate SAN and as the access allowlist (strict mode). Optional; without it the default allowlist applies, see "Network access" |
| `BELAYPOINT_HOSTNAMES` | comma-separated host names for the certificate SAN, e.g. `nas.fritz.box,nas.local` |
| `BELAYPOINT_ALLOW_CIDRS` | additional allowed networks, e.g. a VPN subnet `10.8.0.0/24` |
| `BELAYPOINT_LISTEN` | listen address, default `:8443` (HTTPS only, no plain HTTP listener) |
| `BELAYPOINT_REPOS_DIR` | repository root, default `/repos` |
| `BELAYPOINT_HTPASSWD` | default `<BELAYPOINT_REPOS_DIR>/.htpasswd` (rest-server's default location) |
| `BELAYPOINT_CONFIG_DIR` | own state, default `/config` |
| `BELAYPOINT_MAX_JOBS` | maintenance jobs running at the same time across all repositories (disk load on the NAS), default `1` |
| `BELAYPOINT_LOCK_WAIT` | how long a job waits for other locks to go away (`restic --retry-lock`), default `30m` |
| `BELAYPOINT_SESSION_TTL` | session lifetime, default `8h` |
| `BELAYPOINT_NOTIFY_URL` | webhook for notifications (ntfy-compatible: HTTP POST, text body, `Title` header); empty disables |
| `BELAYPOINT_JOB_LOG_RETENTION` | delete job logs older than this (Go duration), default `2160h` (90 days) |
| `BELAYPOINT_LOG_LEVEL` | `debug`, `info`, `warn`, `error` |
| `TZ` | time zone of schedules and of all times in the UI; an unknown zone is a configuration error |

Configuration changes take effect on restart. There is no hot reload.

## Network access

`internal/netguard` wraps the TCP listener. For every accepted connection the
remote address is checked **before** the TLS handshake; a connection that is
not allowed is closed immediately (no certificate, no HTTP response).

| Mode | Allowed sources |
|---|---|
| Default (no `BELAYPOINT_LAN_ADDRESS`) | loopback, RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), IPv6 ULA `fc00::/7` and link-local `fe80::/10` |
| Strict (`BELAYPOINT_LAN_ADDRESS` set) | only the subnet of `BELAYPOINT_LAN_ADDRESS` (plus loopback) |
| Both modes | plus every network in `BELAYPOINT_ALLOW_CIDRS` |

Additionally, every HTTP request carrying a Cloudflare header (`Cf-Ray`,
`Cf-Connecting-IP`, `Cf-IPCountry`, `Cf-Visitor`, or `Cdn-Loop: cloudflare`)
is rejected and logged as a misconfiguration: such a
request came through the tunnel.

Only the TCP source address counts. `X-Forwarded-For` and similar headers are
ignored; reverse proxies are not supported.

Strict mode is recommended: in default mode a request from another container
(e.g. cloudflared, `172.18.0.x`) would be accepted because its address is
private. With Docker's userland proxy (IPv6 on published ports, hairpin NAT)
the source address can be replaced by the bridge gateway; publishing the port
only on the LAN IPv4 address avoids that path. The filter is defense in depth,
not a replacement for keeping the port off the internet.

## TLS

HTTPS only. Files in `/config/tls/`:

| File | Content |
|---|---|
| `ca.crt`, `ca.key` | local CA, ECDSA P-256, valid 10 years |
| `server.crt`, `server.key` | server certificate signed by the CA, valid 1 year |
| `custom.crt`, `custom.key` | optional, provided by the operator |

At startup (`internal/tlscert`):

1. If `custom.crt` and `custom.key` exist, they are used as they are and
   nothing is generated.
2. Otherwise the CA is created if missing.
3. The server certificate is (re)issued when it is missing, when its SANs
   differ from the configured ones (IP from `BELAYPOINT_LAN_ADDRESS` plus
   `BELAYPOINT_HOSTNAMES`), or when it expires within 30 days. The reason and
   the old and new SHA-256 fingerprints are logged.
4. The SHA-256 fingerprints of the CA and the server certificate are logged at
   every start.

Without `BELAYPOINT_LAN_ADDRESS` and `BELAYPOINT_HOSTNAMES` the server
certificate is issued for `localhost` and `127.0.0.1` only, and a warning is
logged: browsers will report a name mismatch.

Because the CA stays the same, a changed LAN address or a renewal needs no new
trust in the browser once the CA is imported. Without importing the CA, the
browser's exception ("Accept the risk") works too, but must be repeated after
every reissue.

The CA certificate (public part only) can be downloaded from the login page
(`/ca.crt`). Its fingerprint must be compared with the one in the container
log before importing it.

`belaypoint cert reset` (run with `docker exec`) deletes the server
certificate, so the next start issues a new one. `cert reset --ca` also
replaces the CA.

## Vault and sealed state

`/config/vault.json` holds:

- argon2id parameters and salt,
- a key check (a fixed text sealed with AES-256-GCM),
- the sealed secrets by name: `repo:<path>` per repository (the repository
  password), and `totp` (the optional TOTP secret). Each is sealed with the
  vault key, a random nonce and its name as associated data.

The file is written atomically with mode 0600. A file that cannot be parsed,
or whose argon2id parameters are out of bounds, stops the start; it is never
replaced by a new vault.

The vault key is derived from the **admin password** with argon2id. There is
no separate password hash: logging in means deriving the key and opening the
key check. Consequences:

- After a start BelayPoint is **sealed**: no jobs run, the UI shows only the
  login page.
- Logging in unseals: the derived key is kept in memory as `[]byte`. Secrets
  are decrypted when needed; the caller gets its own copy and zeroes it after
  use.
- "Seal now" in the UI or a restart zeroes the key. A job that already got
  its password finishes; the next one is refused.
- Changing the admin password re-encrypts the vault with a new salt.
- On first start (no `vault.json`) BelayPoint prints a one-time **setup
  code** to the container log. The setup page asks for that code and the
  admin password and creates the vault. Without the code, someone on the LAN
  who reaches the page first could take over the instance.
- There is no password recovery. A lost admin password means deleting
  `vault.json` and setting up again; the repository passwords must then be
  entered again.
- "Log out" ends one browser session; the vault stays unsealed and scheduled
  jobs keep running. "Seal now" zeroes the key and ends all sessions.

Sessions are kept in memory only; a restart logs everybody out.

A repository password is entered once per repository in the UI and checked
with `restic cat config` before it is stored. Leading and trailing whitespace
is removed, as restic does for `--password-file` (issue #3). Optionally BelayPoint can add a
dedicated key with `restic key add`, so the client's password is not needed
after that and BelayPoint's access can be revoked separately.

## Repositories

`internal/repos` scans `BELAYPOINT_REPOS_DIR` (up to 3 levels, no symlinks,
hidden entries skipped). A directory is a repository if it contains a `config`
file and the directories `data`, `index`, `keys`, `locks` and `snapshots`.
Repositories are identified by their path relative to the root and mirrored
into the database; a repository that disappears is kept and marked missing.
Discovery runs at startup and on "Rescan", in the background, followed by the
disk usage walk of each repository (stored in the database). Before a
repository directory is used, its path is checked again component by
component: no symlink, no `..`, no hidden component.

Per repository the UI shows:

- disk usage (walk of the directory; works while sealed),
- number and age of lock files (file names and modification times, read live;
  works while sealed; flagged when older than 24 hours),
- snapshot count, newest snapshot, lock details (needs the password: lock files
  are encrypted),
- maintenance plan, last runs and their results.

## Users (`.htpasswd`)

- Listing, adding, resetting the password of, and removing users.
- Hashes: bcrypt. New passwords are generated (shown once) or entered.
- Usernames: `^[a-z0-9][a-z0-9._-]{0,63}$`. With `--private-repos` a user can
  only access repositories below `/<username>/`; the UI shows the repositories
  that belong to each user.
- Writing: temp file in the same directory, `fsync`, `rename`, `fsync` of the
  directory. The directory, not the file, must be mounted (a single-file bind
  mount would keep pointing at the old inode after the rename).
- BelayPoint does not signal the rest-server (no Docker socket). The
  rest-server picks up the change by itself: on requests it checks the file's
  modification time and size at most every 30 s and reloads it; a file it
  cannot parse is ignored and the old users stay active (issue #1). The UI
  says that a change can take up to about 30 s.
- Removing a user does not touch its repositories.

## Maintenance jobs

Job types (all run `restic` with the local backend `-r /repos/<path>`,
`--json`, `--cache-dir /config/cache`, `--retry-lock <BELAYPOINT_LOCK_WAIT>`):

| Job | restic | Lock |
|---|---|---|
| `unlock` | `unlock` (stale locks only) | – |
| `unlock-all` | `unlock --remove-all` (manual only, typed confirmation) | – |
| `forget` | `forget` with the repository's retention policy | exclusive |
| `forget-preview` | `forget --dry-run --no-lock` | none (without `--no-lock` even the dry run takes an exclusive lock) |
| `prune` | `prune --max-unused <policy>` | exclusive |
| `check` | `check --read-data-subset=<n>/<t>` | exclusive |
| `snapshots` | `snapshots` (refresh of the cached snapshot list) | shared |

`check`, `forget` and `prune` take exclusive locks: they cannot run while a
client backs up, and client backups wait (or fail) while they run. Both sides
use `--retry-lock` (issue #2).

### Maintenance plan

Per repository one plan, run as **one job** in a maintenance window (cron
expression):

1. `unlock` (stale locks only)
2. `forget` with the policy (`keep-last/hourly/daily/weekly/monthly/yearly`,
   `keep-within`), grouped by host and paths
3. `prune` (`--max-unused`, default 5 %)
4. `check` with a rotating data subset: run *n* reads subset `n/t`, the next
   run `n+1/t`, so all data is read once every *t* runs (`t` default 7)

Each step can be switched off. A failed step stops the plan; later steps do
not run. Every step can also be started by hand.

### Queue

- At most one job per repository at a time; at most `BELAYPOINT_MAX_JOBS` jobs
  in total.
- Jobs are refused while sealed. A scheduled run that falls into a sealed
  period is recorded as `skipped (sealed)`; a notification is sent once per
  sealed period, listing the skipped runs.
- Sealing during a running job: the job finishes (restic already has the
  password), the secrets are not available for the next job.
- Output is streamed to `/config/jobs/<id>.log` and to the UI (live log).
- After a restart, jobs still marked as running are set to `interrupted`;
  their lock is left to the stale-lock cleanup.

## Notifications

If `BELAYPOINT_NOTIFY_URL` is set: failed jobs, skipped runs while sealed,
lock files older than 24 hours, certificate reissue. The NAS can open outbound
connections, so services like ntfy work.

## Data model (SQLite)

| Table | Content |
|---|---|
| `meta` | schema version |
| `repos` | path (PK), discovered/missing, retention policy (JSON), schedule, step switches, `check_subset_n`, `check_subset_t`, cached snapshot count and newest snapshot |
| `jobs` | id, repo path, type, trigger (manual/schedule), state, started, finished, exit code, summary (JSON) |
| `audit` | time, event, details (login, failed login, seal/unseal, user changes, job starts, settings changes) |

No secrets in the database.
