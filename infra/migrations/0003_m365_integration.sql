-- Microsoft 365 tenant integration tables

-- Store mapping between Comp360Flow tenants and M365 tenants
CREATE TABLE IF NOT EXISTS m365_tenant_mapping (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  m365_tenant_id TEXT NOT NULL,
  m365_tenant_domain TEXT NOT NULL,
  oauth_enabled INTEGER NOT NULL DEFAULT 1,
  auto_provision INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Index for lookups by M365 tenant ID
CREATE INDEX IF NOT EXISTS idx_m365_mapping_tenant_id ON m365_tenant_mapping(m365_tenant_id);

-- Store M365 user mappings for faster lookups and audit trail
CREATE TABLE IF NOT EXISTS m365_users (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  m365_object_id TEXT NOT NULL,
  m365_email TEXT NOT NULL,
  m365_tenant_id TEXT NOT NULL,
  last_login_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(m365_object_id, m365_tenant_id)
);

-- Index for M365 user lookups
CREATE INDEX IF NOT EXISTS idx_m365_users_object_id ON m365_users(m365_object_id);
CREATE INDEX IF NOT EXISTS idx_m365_users_email ON m365_users(m365_email);
CREATE INDEX IF NOT EXISTS idx_m365_users_user_id ON m365_users(user_id);