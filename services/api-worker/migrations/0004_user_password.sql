-- Add password hash and salt columns to users
ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN password_salt TEXT NOT NULL DEFAULT '';
