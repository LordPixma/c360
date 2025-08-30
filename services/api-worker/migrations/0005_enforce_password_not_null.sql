-- Enforce NOT NULL on password columns after backfill.
-- IMPORTANT: Ensure all existing users have password_hash/password_salt before running in production.
-- SQLite doesn't support ALTER COLUMN to add NOT NULL directly when values might be NULL,
-- so we recreate the table with constraints and copy data.

PRAGMA foreign_keys=off;

-- Create new users table with NOT NULL constraints
CREATE TABLE IF NOT EXISTS users_new (
  user_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);

-- Copy only rows that have both password fields populated
INSERT INTO users_new (user_id, tenant_id, email, role, password_hash, password_salt, created_at)
SELECT user_id, tenant_id, email, role, password_hash, password_salt, created_at
FROM users
WHERE password_hash IS NOT NULL AND password_salt IS NOT NULL;

-- Swap tables
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

PRAGMA foreign_keys=on;
