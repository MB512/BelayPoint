-- Audit log (docs/security.md, rule 12). Times are Unix milliseconds (UTC).
CREATE TABLE audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    time    INTEGER NOT NULL,
    event   TEXT    NOT NULL,
    details TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX audit_time ON audit (time);
