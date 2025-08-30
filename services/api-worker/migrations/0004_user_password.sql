-- Add password columns for future authentication. Keep nullable for safe rollout.
ALTER TABLE users ADD COLUMN password_hash TEXT;
ALTER TABLE users ADD COLUMN password_salt TEXT;
