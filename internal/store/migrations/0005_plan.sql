-- Maintenance plan per repository (internal/scheduler): a cron schedule
-- and the steps of the plan job. check_subset_n rotates through
-- 1..check_subset_t, so all data is read once every t runs.
ALTER TABLE repos ADD COLUMN plan_enabled   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE repos ADD COLUMN plan_schedule  TEXT    NOT NULL DEFAULT '';
ALTER TABLE repos ADD COLUMN plan_unlock    INTEGER NOT NULL DEFAULT 1;
ALTER TABLE repos ADD COLUMN plan_forget    INTEGER NOT NULL DEFAULT 1;
ALTER TABLE repos ADD COLUMN plan_prune     INTEGER NOT NULL DEFAULT 1;
ALTER TABLE repos ADD COLUMN plan_check     INTEGER NOT NULL DEFAULT 1;
ALTER TABLE repos ADD COLUMN check_subset_n INTEGER NOT NULL DEFAULT 1;
ALTER TABLE repos ADD COLUMN check_subset_t INTEGER NOT NULL DEFAULT 7;
