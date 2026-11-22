-- Maintenance jobs (internal/jobs) and the cached snapshot summary per
-- repository (written by the snapshots job).
CREATE TABLE jobs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    repo     TEXT    NOT NULL,
    type     TEXT    NOT NULL,
    trigger  TEXT    NOT NULL,             -- manual, schedule
    state    TEXT    NOT NULL,             -- queued, running, succeeded, failed, refused, interrupted
    queued   INTEGER NOT NULL,             -- Unix ms
    started  INTEGER,
    finished INTEGER,
    summary  TEXT    NOT NULL DEFAULT '',  -- short result for the UI
    error    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX jobs_repo ON jobs (repo, id);

ALTER TABLE repos ADD COLUMN snapshot_count  INTEGER; -- NULL until listed
ALTER TABLE repos ADD COLUMN snapshot_newest INTEGER; -- Unix ms, NULL if none
ALTER TABLE repos ADD COLUMN snapshots_time  INTEGER; -- Unix ms of the listing
