-- Archive flag per repository (#7): a closed repository (e.g. a yearly
-- archive) is not reported for an old last backup.
ALTER TABLE repos ADD COLUMN archived INTEGER NOT NULL DEFAULT 0;
