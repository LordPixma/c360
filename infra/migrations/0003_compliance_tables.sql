-- Compliance frameworks, controls, evidence, assessments, tasks, and projects

-- Compliance frameworks (SOC2, ISO27001, etc.)
CREATE TABLE IF NOT EXISTS frameworks (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  version TEXT,
  category TEXT NOT NULL DEFAULT 'security',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Framework enablement per tenant
CREATE TABLE IF NOT EXISTS tenant_frameworks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  framework_id TEXT NOT NULL REFERENCES frameworks(id) ON DELETE CASCADE,
  enabled_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(tenant_id, framework_id)
);

-- Controls within frameworks
CREATE TABLE IF NOT EXISTS controls (
  id TEXT PRIMARY KEY,
  framework_id TEXT REFERENCES frameworks(id) ON DELETE CASCADE,
  tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  control_type TEXT NOT NULL DEFAULT 'manual',
  frequency TEXT NOT NULL DEFAULT 'annual',
  owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'not_started',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_controls_framework ON controls(framework_id);
CREATE INDEX IF NOT EXISTS idx_controls_tenant ON controls(tenant_id);
CREATE INDEX IF NOT EXISTS idx_controls_owner ON controls(owner_user_id);

-- Evidence items
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  file_url TEXT,
  file_type TEXT,
  file_size INTEGER,
  uploaded_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_tenant ON evidence(tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_uploaded_by ON evidence(uploaded_by);

-- Evidence attachments to controls
CREATE TABLE IF NOT EXISTS control_evidence (
  id TEXT PRIMARY KEY,
  control_id TEXT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  attached_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  attached_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(control_id, evidence_id)
);

-- Control assessments/testing
CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY,
  control_id TEXT NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  assessor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'planned',
  result TEXT,
  notes TEXT,
  assessment_date TEXT,
  due_date TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_assessments_control ON assessments(control_id);
CREATE INDEX IF NOT EXISTS idx_assessments_tenant ON assessments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assessments_assessor ON assessments(assessor_user_id);

-- Projects for organizing compliance work
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  manager_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  start_date TEXT,
  end_date TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_projects_tenant ON projects(tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_manager ON projects(manager_user_id);

-- Tasks for compliance activities
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  control_id TEXT REFERENCES controls(id) ON DELETE SET NULL,
  assessment_id TEXT REFERENCES assessments(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  priority TEXT NOT NULL DEFAULT 'medium',
  assigned_to TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  due_date TEXT,
  completed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_tasks_tenant ON tasks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project_id);
CREATE INDEX IF NOT EXISTS idx_tasks_control ON tasks(control_id);
CREATE INDEX IF NOT EXISTS idx_tasks_assigned_to ON tasks(assigned_to);
CREATE INDEX IF NOT EXISTS idx_tasks_created_by ON tasks(created_by);