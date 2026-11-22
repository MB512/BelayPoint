# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
private vulnerability reporting instead: on the repository page, go to
**Security** -> **Report a vulnerability**.

Include what you found, how to reproduce it and which version
(shown in the page footer when logged in, and in the manager's start log)
is affected. You will get an answer as soon as possible; fixes are
released as a new version.

## Supported versions

Only the latest release receives security fixes.

## Scope

BelayPoint can delete backup data (`forget`, `prune`) and holds the
repository passwords while unsealed. The threat model and the rules the code
follows are described in [`docs/security.md`](docs/security.md). In scope
are, for example: reaching BelayPoint from outside the allowed networks,
doing anything without logging in, reading repository passwords from disk
or logs, and deleting data other than through the documented maintenance
actions.
