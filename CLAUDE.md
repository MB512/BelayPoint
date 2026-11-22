# BelayPoint

Self-hosted web app (Go) that manages a
[restic rest-server](https://github.com/restic/rest-server) from the LAN:
users in `.htpasswd`, repository maintenance (`forget`, `prune`, `check`,
stale lock cleanup) on a schedule or by hand. Companion of
[StackBelay](https://github.com/MB512/stackbelay) (formerly StackVault), whose
clients write to the rest-server in append-only mode and therefore can never
delete anything. BelayPoint is the only component that removes backup data,
so it is built to be hard to reach and to keep repository passwords out of
reach of anyone with disk access. Open source (GitHub), MIT.

Read `docs/architecture.md` and `docs/security.md` before changing anything
structural. Keep them in sync with the code.

## Maintainer context

The maintainer is an experienced C#/.NET developer (also C, C++, Java) but new
to Go and to web development. Therefore:

- Prefer boring, idiomatic standard-library solutions over clever ones.
- When introducing a Go idiom the first time (error wrapping, `defer`,
  goroutines/channels, `context`, small interfaces), add a one-line
  explanation in your summary, ideally with the C#/.NET equivalent. Use C#
  only for comparisons and examples, not Rust or other languages.
- Frontend: server-rendered `html/template` + HTMX. No SPA, no Node build step,
  no CDN links (vendor static assets into `internal/web/static`).

## Core concept

One container, one binary, no Docker socket, two mounts:

- `/repos`: the rest-server's data directory (repositories + `.htpasswd`),
  read-write, used by restic with the local backend.
- `/config`: BelayPoint's own state (encrypted vault, SQLite DB, TLS files,
  job logs, restic cache).

The app starts **sealed**. Repository passwords live in an encrypted vault in
`/config`; the key is derived from the admin password and exists only in
memory. Logging in unseals; restarting (or "Seal now") seals again. Scheduled
jobs run only while unsealed; runs that fall into a sealed period are recorded
as skipped and reported.

Maintenance jobs run restic as child processes of the one container, one
exclusive job per repository, globally limited by `BELAYPOINT_MAX_JOBS`.

## Tech decisions (do not change without discussion)

- Go 1.26+, module `github.com/MB512/belaypoint`
- Router: `go-chi/chi`; templates: `html/template`; UI: HTMX
- DB: SQLite via `modernc.org/sqlite` (pure Go, no CGO), embedded SQL migrations
- Scheduler: `robfig/cron/v3`
- Key derivation: argon2id (`golang.org/x/crypto`); vault: AES-256-GCM
- `.htpasswd` hashes: bcrypt (`golang.org/x/crypto/bcrypt`)
- TLS: generated with `crypto/x509` (local CA + server certificate), no
  external tools
- restic is driven through its **CLI** (`restic ... --json`), wrapped behind a
  small interface (`restic.Runner`) so job logic is unit-testable with fakes.
- Logging: `log/slog`. Config: environment variables only (12-factor).
- Same CI and release workflows as StackBelay (`ci.yml`, `release-dev.yml`
  -> `ghcr.io/mb512/belaypoint:dev`, `release.yml` on `v*.*.*` tags).

## Layout

```
cmd/belaypoint/     entrypoint: serve (default), healthcheck, cert reset
internal/config/    env parsing and validation
internal/netguard/  listener wrapper: source-address allowlist, CF header check
internal/tlscert/   local CA + server certificate, SAN check, renewal
internal/vault/     argon2id + AES-GCM vault, sealed/unsealed state, zeroing
internal/auth/      login (= unseal), sessions (memory only), TOTP, rate limit
internal/htpasswd/  parse, validate, atomic write of .htpasswd
internal/repos/     discovery of repositories under /repos, disk usage
internal/restic/    Runner interface + CLI implementation, JSON parsing
internal/jobs/      job types, queue, per-repo exclusivity, logs
internal/scheduler/ cron -> jobs, skipped-while-sealed tracking
internal/notify/    webhook (ntfy-compatible) notifications
internal/store/     SQLite access, migrations (embed)
internal/web/       handlers, templates, static assets
docs/               architecture, security
deploy/             Dockerfile, compose.example.yml
```

## Commands

```
go build ./...
go vet ./...
go test ./... -race
golangci-lint run
docker build -f deploy/Dockerfile -t belaypoint:dev .
```

Run `go vet` and `go test ./... -race` before every commit.

## Conventions

- `gofmt`/`goimports` clean. Wrap errors: `fmt.Errorf("doing X: %w", err)`.
- Pass `context.Context` as first parameter to anything that blocks or does I/O.
- Define interfaces where they are consumed, keep them small.
- No global mutable state, no `init()` side effects.
- Table-driven tests; job tests use a fake `restic.Runner` and must cover:
  lock conflict with retry, job while sealed (refused), seal during a running
  job (job finishes, secrets are not reused afterwards).
- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- Changes are committed directly to `master`, one concern per commit.

## Hard rules (security-critical)

- Never build shell commands from user input. Use `exec.CommandContext` with an
  argument list, never `sh -c`.
- Repository passwords never touch disk in plain text, never appear in CLI
  arguments, environment variables or logs. They reach restic only through
  `--password-file /dev/fd/3` (an `os.Pipe` passed via `cmd.ExtraFiles`).
- Secrets are held as `[]byte` and zeroed after use and on seal. No `string`
  copies of passwords or derived keys.
- Repository paths come only from discovery (directory scan of `/repos`).
  Never accept a free-form path; reject anything not in the discovered set;
  guard against path traversal and symlinks leaving `/repos`.
- Backup data is removed **only** through restic (`forget`, `prune`,
  `unlock`). BelayPoint never deletes files in `/repos` itself, except
  replacing `.htpasswd` atomically.
- `.htpasswd` is written via temp file in the same directory + `fsync` +
  `rename`. Usernames are validated (`internal/htpasswd.ValidName`).
- Every connection passes `internal/netguard` before the TLS handshake.
  Never trust `X-Forwarded-For` or similar headers; there is no reverse proxy
  support.
- Every state-changing endpoint: session + CSRF token + audit log entry.
  Destructive actions (`forget`, `prune`, `unlock --remove-all`) need an
  explicit confirmation; `unlock --remove-all` needs the repository name typed.

## Planning and decisions

Plans, features, bugs and discussions about architecture live in
[GitHub issues](https://github.com/MB512/belaypoint/issues), not in the repo.
Repo files (code, `docs/`, README) describe the current state only: no
milestones, TODO lists, "planned"/"open" sections or roadmaps. Design
decisions are recorded in `docs/` as the outcome of the issue discussion
(reference the issue number). `TODO` code comments are fine.

## Out of scope

Docker socket access, worker containers, self-update, multiple users or roles,
reverse proxy / internet exposure, remote restic backends (only the local
`/repos` mount), creating or deleting repositories (clients `init`, deletion is
done on the NAS by hand), restoring data.
