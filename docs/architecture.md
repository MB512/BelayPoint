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
  the owner of the first repository's `config` file (the user the rest-server
  writes as; `/repos` itself if there is no repository yet) and logs a
  warning on mismatch. A rest-server without `user:` runs as root; then
  BelayPoint must run as root too (`user: "0:0"`).
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
only on the LAN IPv4 address avoids that path. Some NAS systems (seen on
Synology DSM) replace it even then: the log shows dropped connections from
`172.x.0.1`, and BelayPoint adds a hint. Then run the container with
`network_mode: host` (without `ports:` and `networks:`). Never allow the
gateway address: every forwarded connection would carry it. The filter is defense in depth,
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

A repository password is entered once per repository in the UI (overview,
"Password" column) and checked with `restic cat config` before it is stored.
Leading and trailing whitespace is removed, as restic does for
`--password-file` (issue #3). A stored password can be removed again; only
BelayPoint loses access. Without a restic binary BelayPoint still starts;
passwords then cannot be checked or stored. Optionally BelayPoint can add a
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

- disk usage (walk of the directory; works while sealed) with a bar scaled
  to the largest repository and its share of the total,
- number and age of lock files (file names and modification times, read live;
  works while sealed; flagged when older than 24 hours),
- snapshot count and age of the newest snapshot, cached from the last
  `snapshots` job (needs the password; queued automatically after a password
  is stored, and by "Refresh snapshots" for one or all repositories),
- lock details (needs the password: lock files are encrypted),
- maintenance plan, last runs and their results.

Every page behind the login shows a bar with the used and free space of the
volume holding `/repos` (statfs), with the backups' total on the overview. It
turns yellow at 80 % and red with a warning at 90 %: `prune` needs free space
to rewrite packs.

Below the repository table, a per-user summary (the user is the first path component, as with
`--private-repos`) sums repositories, size and files, largest first, with a
total. Missing repositories are not counted; repositories not measured yet
are counted but marked, since their size is not in the sum.

### Storage page

The Storage page (#7) shows the free space of the volume as the leading
figure, then the volume as one segmented bar: a block per user, "other data"
(used space of the volume minus the backups) and free space, with a legend
table (repositories, size, share). Below, the repositories as bars ranked by
size, scaled to the largest, and a collapsed details table (files, measured).
"Measure again" starts the background measurement and returns to the page.

- A user keeps one colour everywhere: users get the categorical slots in
  alphabetical order (not by size, so a colour never moves when sizes
  change). Eight slots; further users are folded into "other users"
  instead of generating colours that cannot be told apart. The palette was
  checked for colour-vision deficiency against the card surface in light
  and dark mode; every colour is also named in the legend.
- The charts are inline SVG rendered on the server: no JavaScript, and
  widths are SVG attributes because the CSP forbids `style` attributes.
  Each block and bar has a tooltip (`<title>`) and an accessible name.
- If the backups are larger than the volume's used space (quota, other
  file system reporting), the whole is at least the backups, so the bar
  never exceeds 100 %.

## Users (`.htpasswd`)

- Listing, adding, resetting the password of, and removing users. Reset and
  remove need a confirmation page.
- Hashes: bcrypt (cost 10: the rest-server checks hashes on requests, so the
  NAS CPU sets the limit). New passwords are generated (160 bits, shown once,
  never stored or logged) or entered (12 to 72 bytes, bcrypt's limit).
  Existing entries with other hash types are kept and flagged in the UI;
  resetting the password replaces them with bcrypt.
- Comments and blank lines in the file are kept. A missing file counts as no
  users and is created on the first add.
- Usernames: `^[a-z0-9][a-z0-9._-]{0,63}$`. With `--private-repos` a user can
  only access repositories below `/<username>/`; the UI shows the repositories
  that belong to each user and the repositories without a user.
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

`internal/restic` wraps the CLI behind the `restic.Runner` interface. It
recognizes restic's exit codes for a wrong password (12; restic before
0.17.1 exits with 1 and is matched by its message), a missing repository (10)
and a lock conflict (11). Cancelling a run (shutdown, a cancelled job) sends
SIGINT, so restic removes its own lock; restic is killed only if it has not
exited after 30 seconds. Read-only commands (`cat config`, `snapshots`) run
with `--no-lock`.

### Retention policy and preview

Each repository has a page (path link in the overview) with its retention
policy: keep last / hourly / daily / weekly / monthly / yearly and keep
within (a restic duration such as `14d` or `1y6m`), grouped by host and
paths. A policy without any rule is refused (restic would keep everything).
Values are validated and passed as separate arguments.

**Tag rules** give snapshots with a tag their own retention (up to 5 rules,
each with the same keep values as the policy). The page shows the policy as
one table: a row per tag rule, an empty row to add one, and a last row
*all other snapshots* with the main policy. Each rule row has a × button that
saves the policy without that rule; a row with values but no tag is refused
rather than dropped. forget then runs in
passes: first one per rule (`forget --tag <tag>` with the rule's values),
then the main policy over the snapshots *without* a rule tag only. restic
has no "without tag" filter, and `--keep-tag` is no help: protected
snapshots still take keep slots of the main policy (a pre-stop snapshot
would push a final snapshot out of keep-last). So BelayPoint lists the
snapshots first (`--no-lock`) and passes the main policy the tag
combinations found that contain no rule tag (`--tag final --tag ''`, where
`''` selects untagged snapshots). A snapshot that has a rule tag *and* all
tags of such a combination (e.g. `final,pre-stop`) would be selected twice;
forget then refuses with an error instead of guessing. Snapshots created
between the listing and the main pass with a new tag combination are left
alone.

The default policy, for repositories without their own: daily 7, weekly 4,
monthly 12, yearly 3, and the tag rule `pre-stop`: keep last 2. StackBelay
takes a `pre-stop` snapshot while a stack still runs (not consistent), then
the consistent `final` snapshot; the rule keeps the two newest pre-stop
snapshots per host and paths. In repositories without such snapshots the
rule removes nothing.

"Preview these values" runs every pass with `forget --dry-run --no-lock` with
the values in the form, without saving them. The result is headed "Preview of
the unsaved values" (with a hint to save) when they differ from the saved
policy, "Preview of the saved policy" otherwise. It lists per pass and group which
snapshots would be kept and removed. The passes see disjoint sets of
snapshots, so the dry runs add up to what forget would do. It runs right away, outside the job queue: it is read-only and takes
no lock, so it cannot conflict with jobs or client backups.

### Repository page

The repository page has three tabs, plain links with `?tab=` (no
JavaScript; only the active tab is rendered, and saving returns to it):
**Run now** (the default), **Retention** (policy table and preview) and
**Schedule** (maintenance plan). Owner, password status, next scheduled run
and whether the policy is the default stay above the tabs.

### Running maintenance by hand

The Run now tab has one block per action: "Unlock" (stale locks; "Remove all
locks…" leads to the typed confirmation of `unlock --remove-all`),
"Forget…", "Prune…" and "Check". It needs the repository password. A job
started by hand leads straight to
its log page; a refused job is reported on the page it was started from.
forget and prune open a confirmation page; check runs directly. The forget
confirmation page runs the dry-run with the saved policy (like "Preview these
values") and shows what would be removed; "Run forget" below it is the
confirmation. If the dry-run fails, the page offers no confirmation, so
nobody runs a forget without seeing its effect. prune needs a ticked
checkbox. forget uses the saved policy (or the
default), logs every removed snapshot and updates the cached snapshot summary
from restic's result. prune uses `--max-unused 5%`. A check started by hand
verifies the structure only, or with "read part n of t" also that data
subset (`--read-data-subset n/t`, 1 ≤ n ≤ t ≤ 365); it does not advance the
plan's rotation. forget, prune and check wait up to
`BELAYPOINT_LOCK_WAIT` for other locks (`--retry-lock`) and then fail with a
lock error.

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
not run. The check rotation advances only after a successful check; `t = 0`
checks the structure only. Every step can also be started by hand on the
Run now tab; the plan as a whole runs only on its schedule.

The plan is set on the Schedule tab of the repository page: schedule, steps and rotation, off by
default. The schedule is a 5-field cron expression (minute hour day month
weekday) or `@daily` / `@weekly` / `@monthly` in the container's time zone
(`TZ`), with at least one hour between runs; `@every` is refused.
`internal/scheduler` (robfig/cron) holds one entry per present repository
with an enabled plan and reloads them when a plan is saved. At the scheduled
time it queues the plan job; if the job is refused (vault sealed, no
password, a job for the repository still queued or running), the run is
recorded as a job with state `skipped` and the reason.

### Queue

- At most one job per repository at a time; at most `BELAYPOINT_MAX_JOBS` jobs
  in total.
- Jobs need an unsealed vault and a stored password for the repository. The
  password is fetched from the vault only when a job starts, so a job that
  waited in the queue while the vault was sealed ends as `refused`. At most
  256 jobs wait in the queue.
- A scheduled run that falls into a sealed period is recorded as
  `skipped (sealed)`; a notification is sent once per sealed period, listing
  the skipped runs.
- Sealing during a running job: the job finishes (restic already has the
  password), the secrets are not available for the next job.
- restic's output goes to `/config/jobs/<id>.log` (mode 0600), with the
  repository password replaced by `[redacted]` should restic ever print it.
  The "Jobs" page links each job to its log. The log page shows the job's
  state and result above the log and reloads itself every 2 seconds
  (`<meta http-equiv="refresh">`, no JavaScript) while the job is queued or
  running. Logs older than
  `BELAYPOINT_JOB_LOG_RETENTION` are removed at startup and daily.
- Locks: the overview shows the lock files per repository (count and age,
  read live) and links them to the Run now tab, which shows them again and
  offers "Unlock" (`unlock`: restic removes locks whose process is gone on
  the same host, or that were not refreshed for 30 minutes) and "Remove all
  locks…" (`unlock --remove-all` on a page that warns and needs the
  repository name typed).
- States: `queued`, `running`, `succeeded`, `failed`, `refused`,
  `interrupted`, `skipped` (a scheduled run that could not start). The "Jobs" page lists them, newest first.
- After a restart, jobs still marked as queued or running are set to
  `interrupted`; their lock is left to the stale-lock cleanup.

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
