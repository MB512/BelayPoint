# BelayPoint

**The anchor for your backups.** A small web app that manages a
[restic rest-server](https://github.com/restic/rest-server) from your LAN:

- users in `.htpasswd`
- repository maintenance: `forget`, `prune`, `check`, stale lock cleanup,
  on a schedule or by hand, with live logs
- disk usage, snapshot and lock overview per repository

BelayPoint is the companion of [StackBelay](https://github.com/MB512/stackbelay),
which backs up Docker Compose stacks to a rest-server in append-only mode.
Append-only clients can never delete their backups, so retention has to
happen on the server side. That is BelayPoint's job.

> Never climb without a belay. Never update without a backup.

## Design in short

- **LAN only.** Connections from outside the allowed networks are dropped
  before the TLS handshake. Not meant to be exposed to the internet, not even
  behind a reverse proxy.
- **Sealed after every start.** Repository passwords are stored encrypted;
  the key comes from your admin password and exists only in memory. Disk
  access to the NAS is not enough to read your backups.
- **No host access.** No Docker socket, no extra containers. One container,
  two mounts: the rest-server's data directory and BelayPoint's own state.
- **HTTPS with its own local CA.** Import the CA into your browser once, or
  accept the certificate exception.

Details: [`docs/architecture.md`](docs/architecture.md) and
[`docs/security.md`](docs/security.md).

## Status

Early design phase, no release yet.

## License

[MIT](LICENSE)
