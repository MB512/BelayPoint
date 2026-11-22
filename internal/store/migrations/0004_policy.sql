-- Retention policy per repository as JSON (restic.Policy); NULL means the
-- default policy.
ALTER TABLE repos ADD COLUMN policy TEXT;
