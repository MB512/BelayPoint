-- "Password kept by the owner": BelayPoint intentionally has no password
-- for the repository (e.g. a relative's or friend's backups), so it is not
-- reported as missing one. Cleared when a password is stored.
ALTER TABLE repos ADD COLUMN owner_key INTEGER NOT NULL DEFAULT 0;
