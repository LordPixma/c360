-- Initial schema for Comp360Flow (D1)

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  slug TEXT UNIQUE,
  name TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'starter',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  name TEXT,
  role TEXT NOT NULL DEFAULT 'company_admin',
  status TEXT NOT NULL DEFAULT 'active',
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  password_iter INTEGER NOT NULL,
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_secret TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(tenant_id, email)
);

CREATE TABLE IF NOT EXISTS branding (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  logo_text TEXT NOT NULL DEFAULT 'Comp360Flow',
  primary_color TEXT NOT NULL DEFAULT '#0b62d6',
  secondary_color TEXT NOT NULL DEFAULT '#eef6ff',
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
