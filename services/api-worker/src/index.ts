type Env = {
  SESSION_SECRET: string;
  TURNSTILE_SECRET_KEY?: string;
  DB: D1Database;
  // cache provided by platform
  __STATIC_CONTENT?: unknown;
};

const text = (body: string, status = 200, headers: HeadersInit = {}) =>
  new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8', ...headers } });
const json = (data: unknown, status = 200, headers: HeadersInit = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...headers } });

function parseUrl(req: Request) {
  const url = new URL(req.url);
  return { url, path: url.pathname, method: req.method.toUpperCase() };
}

function cors(req: Request, resHeaders: Headers) {
  const origin = req.headers.get('origin') || '*';
  resHeaders.set('access-control-allow-origin', origin);
  resHeaders.set('vary', 'origin');
  resHeaders.set('access-control-allow-credentials', 'true');
  resHeaders.set('access-control-allow-headers', 'content-type');
  resHeaders.set('access-control-allow-methods', 'GET,POST,OPTIONS');
}

async function readJson<T>(req: Request): Promise<T | null> {
  try { return await req.json(); } catch { return null; }
}

async function hmac(env: Env, payload: string): Promise<string> {
  const secret = env.SESSION_SECRET || 'dev_session_secret_change_me';
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function verifyHmac(env: Env, payload: string, signature: string): Promise<boolean> {
  const expected = await hmac(env, payload);
  // timing-safe compare (simple constant-time-ish)
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return diff === 0;
}

type Session = { sub: string; email: string; tenant?: string; exp: number };

function toCookie(value: string, maxAgeSeconds: number) {
  return `c360_session=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`;
}

function getCookie(req: Request, name: string) {
  const cookie = req.headers.get('cookie') || '';
  const parts = cookie.split(/;\s*/);
  for (const p of parts) {
    const [k, v] = p.split('=');
    if (k === name) return v;
  }
  return undefined;
}

async function createSession(env: Env, data: Omit<Session, 'exp'>, ttlSeconds: number) {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const payload = btoa(JSON.stringify({ ...data, exp } satisfies Session));
  const signature = await hmac(env, payload);
  return `${payload}.${signature}`;
}

async function verifySession(env: Env, token?: string): Promise<Session | null> {
  if (!token) return null;
  const [payload, signature] = token.split('.', 2);
  if (!payload || !signature) return null;
  const ok = await verifyHmac(env, payload, signature);
  if (!ok) return null;
  try {
    const sess = JSON.parse(atob(payload)) as Session;
    if (sess.exp < Math.floor(Date.now() / 1000)) return null;
    return sess;
  } catch { return null; }
}

// Crypto helpers
async function pbkdf2(password: string, salt: Uint8Array, iterations = 100_000, length = 32): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: (salt as unknown as BufferSource), iterations, hash: 'SHA-256' }, key, length * 8);
  return new Uint8Array(bits);
}
function hex(bytes: Uint8Array) { return [...bytes].map(b => b.toString(16).padStart(2, '0')).join(''); }

// TOTP (RFC 6238) minimal impl
async function hotp(secret: Uint8Array, counter: number, digits = 6): Promise<string> {
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  // big-endian
  view.setUint32(4, counter);
  const key = await crypto.subtle.importKey('raw', (secret as unknown as BufferSource), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const hmacRes = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBuf));
  const offset = hmacRes[hmacRes.length - 1] & 0xf;
  const code = ((hmacRes[offset] & 0x7f) << 24) | ((hmacRes[offset + 1] & 0xff) << 16) | ((hmacRes[offset + 2] & 0xff) << 8) | (hmacRes[offset + 3] & 0xff);
  const hotpVal = (code % 10 ** digits).toString().padStart(digits, '0');
  return hotpVal;
}
async function totp(secret: Uint8Array, timeStep = 30, digits = 6, t = Math.floor(Date.now() / 1000)) {
  const counter = Math.floor(t / timeStep);
  return hotp(secret, counter, digits);
}
function decodeBase32(s: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/=+$/,'')) {
    const val = alphabet.indexOf(c.toUpperCase());
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const out: number[] = [];
  for (let i=0;i+8<=bits.length;i+=8) out.push(parseInt(bits.slice(i,i+8), 2));
  return new Uint8Array(out);
}

function fromHex(hexStr: string): Uint8Array {
  const clean = hexStr.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

// DB helpers
async function getTenantBySlug(env: Env, slug: string): Promise<{ id: string, name: string } | null> {
  const r = await env.DB.prepare('SELECT id, name FROM tenants WHERE slug = ?').bind(slug).first<{ id: string, name: string }>();
  return r ?? null;
}
async function ensureTenant(env: Env, slug: string, name: string): Promise<{ id: string }>{
  const found = await env.DB.prepare('SELECT id FROM tenants WHERE slug = ?').bind(slug).first<{ id: string }>();
  if (found) return found;
  const id = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO tenants(id, slug, name, plan) VALUES(?, ?, ?, ?)').bind(id, slug, name, 'starter').run();
  await env.DB.prepare('INSERT INTO branding(tenant_id) VALUES(?)').bind(id).run();
  return { id };
}
async function getUserByEmail(env: Env, tenantId: string, email: string) {
  return await env.DB.prepare('SELECT * FROM users WHERE tenant_id = ? AND email = ?').bind(tenantId, email).first<any>();
}
async function getUserById(env: Env, tenantId: string, userId: string) {
  return await env.DB.prepare('SELECT * FROM users WHERE tenant_id = ? AND id = ?').bind(tenantId, userId).first<any>();
}
async function listUsers(env: Env, tenantId: string, limit: string = '50', offset: string = '0') {
  return await env.DB.prepare('SELECT id, email, name, role, status, created_at FROM users WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(tenantId, limit, offset).all<any>();
}
async function updateUser(env: Env, tenantId: string, userId: string, updates: { name?: string; role?: string; status?: string }) {
  const fields = [];
  const values = [];
  if (updates.name !== undefined) { fields.push('name = ?'); values.push(updates.name); }
  if (updates.role !== undefined) { fields.push('role = ?'); values.push(updates.role); }
  if (updates.status !== undefined) { fields.push('status = ?'); values.push(updates.status); }
  if (fields.length === 0) return false;
  const query = `UPDATE users SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`;
  await env.DB.prepare(query).bind(...values, tenantId, userId).run();
  return true;
}
async function deactivateUser(env: Env, tenantId: string, userId: string) {
  await env.DB.prepare('UPDATE users SET status = ? WHERE tenant_id = ? AND id = ?').bind('inactive', tenantId, userId).run();
  return true;
}
async function insertUser(env: Env, tenantId: string, email: string, name: string, password: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iter = 100_000;
  const hash = await pbkdf2(password, salt, iter);
  const id = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO users(id, tenant_id, email, name, role, status, password_hash, password_salt, password_iter) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, tenantId, email, name, 'company_admin', 'active', hex(hash), hex(salt), iter).run();
  return { id };
}
async function setUserMfa(env: Env, userId: string, secretBase32: string) {
  await env.DB.prepare('UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE id = ?').bind(secretBase32, userId).run();
}
async function createRecoveryCodes(env: Env, userId: string): Promise<string[]> {
  const codes: string[] = [];
  for (let i=0;i<8;i++) {
    const raw = crypto.randomUUID().replace(/-/g,'').slice(0,10);
    const hash = await hmac({ SESSION_SECRET: 'recovery', DB: env.DB } as Env, raw);
    await env.DB.prepare('INSERT INTO recovery_codes(id, user_id, code_hash) VALUES(?, ?, ?)').bind(crypto.randomUUID(), userId, hash).run();
    codes.push(raw);
  }
  return codes;
}
async function consumeRecoveryCode(env: Env, userId: string, code: string): Promise<boolean> {
  const hash = await hmac({ SESSION_SECRET: 'recovery', DB: env.DB } as Env, code);
  const found = await env.DB.prepare('SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL').bind(userId, hash).first<any>();
  if (!found) return false;
  await env.DB.prepare('UPDATE recovery_codes SET used_at = (strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\')) WHERE id = ?').bind(found.id).run();
  return true;
}
async function mapDomainToTenant(env: Env, domain: string): Promise<string | null> {
  const r = await env.DB.prepare('SELECT tenant_id FROM tenant_domains WHERE domain = ?').bind(domain.toLowerCase()).first<{ tenant_id: string }>();
  return r?.tenant_id || null;
}
async function setDomainMapping(env: Env, domain: string, tenantId: string) {
  await env.DB.prepare('INSERT OR REPLACE INTO tenant_domains(domain, tenant_id) VALUES(?, ?)').bind(domain.toLowerCase(), tenantId).run();
}
async function createInvite(env: Env, tenantId: string, email: string, role: string, hours = 72) {
  const id = crypto.randomUUID();
  const token = crypto.randomUUID();
  const expires = new Date(Date.now() + hours * 3600 * 1000).toISOString();
  await env.DB.prepare('INSERT INTO invites(id, tenant_id, email, role, token, status, expires_at) VALUES(?, ?, ?, ?, ?, ?, ?)').bind(id, tenantId, email.toLowerCase(), role, token, 'pending', expires).run();
  return { id, token, expires_at: expires };
}
async function acceptInvite(env: Env, token: string, name: string, password: string) {
  const inv = await env.DB.prepare('SELECT * FROM invites WHERE token = ? AND status = \"pending\" AND expires_at > (strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'))').bind(token).first<any>();
  if (!inv) return null;
  const { id: userId } = await insertUser(env, inv.tenant_id, inv.email, name, password);
  await env.DB.prepare('UPDATE invites SET status = \"accepted\" WHERE id = ?').bind(inv.id).run();
  return { tenantId: inv.tenant_id, userId, email: inv.email };
}
async function getBranding(env: Env, tenantId: string) {
  return await env.DB.prepare('SELECT logo_text, primary_color, secondary_color FROM branding WHERE tenant_id = ?').bind(tenantId).first<any>();
}
async function setBranding(env: Env, tenantId: string, logoText: string, primary: string, secondary: string) {
  await env.DB.prepare('INSERT INTO branding(tenant_id, logo_text, primary_color, secondary_color) VALUES(?, ?, ?, ?) ON CONFLICT(tenant_id) DO UPDATE SET logo_text=excluded.logo_text, primary_color=excluded.primary_color, secondary_color=excluded.secondary_color, updated_at=(strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'))').bind(tenantId, logoText, primary, secondary).run();
}
async function updateTenant(env: Env, tenantId: string, updates: { name?: string; plan?: string }) {
  const fields = [];
  const values = [];
  if (updates.name !== undefined) { fields.push('name = ?'); values.push(updates.name); }
  if (updates.plan !== undefined) { fields.push('plan = ?'); values.push(updates.plan); }
  if (fields.length === 0) return false;
  const query = `UPDATE tenants SET ${fields.join(', ')} WHERE id = ?`;
  await env.DB.prepare(query).bind(...values, tenantId).run();
  return true;
}
async function getTenantSettings(env: Env, tenantId: string) {
  return await env.DB.prepare('SELECT slug, name, plan, created_at FROM tenants WHERE id = ?').bind(tenantId).first<any>();
}
async function createAuditLog(env: Env, tenantId: string, actorUserId: string | null, action: string, target?: string, details?: any) {
  const id = crypto.randomUUID();
  const detailsJson = details ? JSON.stringify(details) : null;
  await env.DB.prepare('INSERT INTO audit_log(id, tenant_id, actor_user_id, action, target, details_json) VALUES(?, ?, ?, ?, ?, ?)').bind(id, tenantId, actorUserId, action, target, detailsJson).run();
  return { id };
}
async function getAuditLogs(env: Env, tenantId: string, limit: string = '50', offset: string = '0') {
  return await env.DB.prepare('SELECT al.*, u.name as actor_name, u.email as actor_email FROM audit_log al LEFT JOIN users u ON al.actor_user_id = u.id WHERE al.tenant_id = ? ORDER BY al.ts DESC LIMIT ? OFFSET ?').bind(tenantId, limit, offset).all<any>();
}

// Compliance Framework functions
async function getFrameworks(env: Env) {
  return await env.DB.prepare('SELECT * FROM frameworks WHERE active = 1 ORDER BY name').all<any>();
}
async function getTenantFrameworks(env: Env, tenantId: string) {
  return await env.DB.prepare('SELECT f.*, tf.enabled_at FROM frameworks f INNER JOIN tenant_frameworks tf ON f.id = tf.framework_id WHERE tf.tenant_id = ? ORDER BY f.name').bind(tenantId).all<any>();
}
async function enableFrameworkForTenant(env: Env, tenantId: string, frameworkId: string) {
  const id = crypto.randomUUID();
  await env.DB.prepare('INSERT OR IGNORE INTO tenant_frameworks(id, tenant_id, framework_id) VALUES(?, ?, ?)').bind(id, tenantId, frameworkId).run();
  return { id };
}
async function disableFrameworkForTenant(env: Env, tenantId: string, frameworkId: string) {
  await env.DB.prepare('DELETE FROM tenant_frameworks WHERE tenant_id = ? AND framework_id = ?').bind(tenantId, frameworkId).run();
  return true;
}

// Control functions
async function getControls(env: Env, tenantId: string, frameworkId?: string, limit: string = '50', offset: string = '0') {
  if (frameworkId) {
    return await env.DB.prepare('SELECT c.*, u.name as owner_name FROM controls c LEFT JOIN users u ON c.owner_user_id = u.id WHERE c.tenant_id = ? AND c.framework_id = ? ORDER BY c.code LIMIT ? OFFSET ?').bind(tenantId, frameworkId, limit, offset).all<any>();
  }
  return await env.DB.prepare('SELECT c.*, u.name as owner_name, f.name as framework_name FROM controls c LEFT JOIN users u ON c.owner_user_id = u.id LEFT JOIN frameworks f ON c.framework_id = f.id WHERE c.tenant_id = ? ORDER BY c.code LIMIT ? OFFSET ?').bind(tenantId, limit, offset).all<any>();
}
async function getControlById(env: Env, tenantId: string, controlId: string) {
  return await env.DB.prepare('SELECT c.*, u.name as owner_name, f.name as framework_name FROM controls c LEFT JOIN users u ON c.owner_user_id = u.id LEFT JOIN frameworks f ON c.framework_id = f.id WHERE c.tenant_id = ? AND c.id = ?').bind(tenantId, controlId).first<any>();
}
async function createControl(env: Env, tenantId: string, control: { frameworkId?: string; code: string; title: string; description?: string; controlType?: string; frequency?: string; ownerUserId?: string }) {
  const id = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO controls(id, framework_id, tenant_id, code, title, description, control_type, frequency, owner_user_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(id, control.frameworkId || null, tenantId, control.code, control.title, control.description || '', control.controlType || 'manual', control.frequency || 'annual', control.ownerUserId || null).run();
  return { id };
}
async function updateControl(env: Env, tenantId: string, controlId: string, updates: { title?: string; description?: string; controlType?: string; frequency?: string; ownerUserId?: string; status?: string }) {
  const fields = [];
  const values = [];
  if (updates.title !== undefined) { fields.push('title = ?'); values.push(updates.title); }
  if (updates.description !== undefined) { fields.push('description = ?'); values.push(updates.description); }
  if (updates.controlType !== undefined) { fields.push('control_type = ?'); values.push(updates.controlType); }
  if (updates.frequency !== undefined) { fields.push('frequency = ?'); values.push(updates.frequency); }
  if (updates.ownerUserId !== undefined) { fields.push('owner_user_id = ?'); values.push(updates.ownerUserId); }
  if (updates.status !== undefined) { fields.push('status = ?'); values.push(updates.status); }
  if (fields.length === 0) return false;
  fields.push('updated_at = (strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'))');
  const query = `UPDATE controls SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`;
  await env.DB.prepare(query).bind(...values, tenantId, controlId).run();
  return true;
}

// Task Management functions
async function getTasks(env: Env, tenantId: string, filters: { assignedTo?: string; project?: string; status?: string; } = {}, limit = 50, offset = 0) {
  let query = 'SELECT t.*, u_assigned.name as assigned_to_name, u_created.name as created_by_name, p.name as project_name FROM tasks t LEFT JOIN users u_assigned ON t.assigned_to = u_assigned.id LEFT JOIN users u_created ON t.created_by = u_created.id LEFT JOIN projects p ON t.project_id = p.id WHERE t.tenant_id = ?';
  const params = [tenantId];
  
  if (filters.assignedTo) { query += ' AND t.assigned_to = ?'; params.push(filters.assignedTo); }
  if (filters.project) { query += ' AND t.project_id = ?'; params.push(filters.project); }
  if (filters.status) { query += ' AND t.status = ?'; params.push(filters.status); }
  
  query += ' ORDER BY t.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit.toString(), offset.toString());
  
  return await env.DB.prepare(query).bind(...params).all<any>();
}
async function getTaskById(env: Env, tenantId: string, taskId: string) {
  return await env.DB.prepare('SELECT t.*, u_assigned.name as assigned_to_name, u_created.name as created_by_name, p.name as project_name FROM tasks t LEFT JOIN users u_assigned ON t.assigned_to = u_assigned.id LEFT JOIN users u_created ON t.created_by = u_created.id LEFT JOIN projects p ON t.project_id = p.id WHERE t.tenant_id = ? AND t.id = ?').bind(tenantId, taskId).first<any>();
}
async function createTask(env: Env, tenantId: string, task: { title: string; description?: string; projectId?: string; controlId?: string; assignedTo?: string; priority?: string; dueDate?: string }, createdBy: string) {
  const id = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO tasks(id, tenant_id, project_id, control_id, title, description, priority, assigned_to, created_by, due_date) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(id, tenantId, task.projectId || null, task.controlId || null, task.title, task.description || '', task.priority || 'medium', task.assignedTo || null, createdBy, task.dueDate || null).run();
  return { id };
}
async function updateTask(env: Env, tenantId: string, taskId: string, updates: { title?: string; description?: string; status?: string; priority?: string; assignedTo?: string; dueDate?: string }) {
  const fields = [];
  const values = [];
  if (updates.title !== undefined) { fields.push('title = ?'); values.push(updates.title); }
  if (updates.description !== undefined) { fields.push('description = ?'); values.push(updates.description); }
  if (updates.status !== undefined) { fields.push('status = ?'); values.push(updates.status); }
  if (updates.priority !== undefined) { fields.push('priority = ?'); values.push(updates.priority); }
  if (updates.assignedTo !== undefined) { fields.push('assigned_to = ?'); values.push(updates.assignedTo); }
  if (updates.dueDate !== undefined) { fields.push('due_date = ?'); values.push(updates.dueDate); }
  if (fields.length === 0) return false;
  
  // Set completed_at if status is changed to completed
  if (updates.status === 'completed') {
    fields.push('completed_at = (strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'))');
  }
  
  fields.push('updated_at = (strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'))');
  const query = `UPDATE tasks SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`;
  await env.DB.prepare(query).bind(...values, tenantId, taskId).run();
  return true;
}

// Project Management functions
async function getProjects(env: Env, tenantId: string, limit: string = '50', offset: string = '0') {
  return await env.DB.prepare('SELECT p.*, u.name as manager_name FROM projects p LEFT JOIN users u ON p.manager_user_id = u.id WHERE p.tenant_id = ? ORDER BY p.created_at DESC LIMIT ? OFFSET ?').bind(tenantId, limit, offset).all<any>();
}
async function getProjectById(env: Env, tenantId: string, projectId: string) {
  return await env.DB.prepare('SELECT p.*, u.name as manager_name FROM projects p LEFT JOIN users u ON p.manager_user_id = u.id WHERE p.tenant_id = ? AND p.id = ?').bind(tenantId, projectId).first<any>();
}
async function createProject(env: Env, tenantId: string, project: { name: string; description?: string; managerUserId?: string; startDate?: string; endDate?: string }) {
  const id = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO projects(id, tenant_id, name, description, manager_user_id, start_date, end_date) VALUES(?, ?, ?, ?, ?, ?, ?)').bind(id, tenantId, project.name, project.description || '', project.managerUserId || null, project.startDate || null, project.endDate || null).run();
  return { id };
}
async function updateProject(env: Env, tenantId: string, projectId: string, updates: { name?: string; description?: string; status?: string; managerUserId?: string; startDate?: string; endDate?: string }) {
  const fields = [];
  const values = [];
  if (updates.name !== undefined) { fields.push('name = ?'); values.push(updates.name); }
  if (updates.description !== undefined) { fields.push('description = ?'); values.push(updates.description); }
  if (updates.status !== undefined) { fields.push('status = ?'); values.push(updates.status); }
  if (updates.managerUserId !== undefined) { fields.push('manager_user_id = ?'); values.push(updates.managerUserId); }
  if (updates.startDate !== undefined) { fields.push('start_date = ?'); values.push(updates.startDate); }
  if (updates.endDate !== undefined) { fields.push('end_date = ?'); values.push(updates.endDate); }
  if (fields.length === 0) return false;
  fields.push('updated_at = (strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'))');
  const query = `UPDATE projects SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`;
  await env.DB.prepare(query).bind(...values, tenantId, projectId).run();
  return true;
}

// Evidence Management functions
async function getEvidence(env: Env, tenantId: string, limit: string = '50', offset: string = '0') {
  return await env.DB.prepare('SELECT e.*, u.name as uploaded_by_name FROM evidence e LEFT JOIN users u ON e.uploaded_by = u.id WHERE e.tenant_id = ? ORDER BY e.created_at DESC LIMIT ? OFFSET ?').bind(tenantId, limit, offset).all<any>();
}
async function getEvidenceById(env: Env, tenantId: string, evidenceId: string) {
  return await env.DB.prepare('SELECT e.*, u.name as uploaded_by_name FROM evidence e LEFT JOIN users u ON e.uploaded_by = u.id WHERE e.tenant_id = ? AND e.id = ?').bind(tenantId, evidenceId).first<any>();
}
async function createEvidence(env: Env, tenantId: string, evidence: { name: string; description?: string; fileUrl?: string; fileType?: string; fileSize?: number }, uploadedBy: string) {
  const id = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO evidence(id, tenant_id, name, description, file_url, file_type, file_size, uploaded_by) VALUES(?, ?, ?, ?, ?, ?, ?, ?)').bind(id, tenantId, evidence.name, evidence.description || '', evidence.fileUrl || null, evidence.fileType || null, evidence.fileSize || null, uploadedBy).run();
  return { id };
}
async function updateEvidence(env: Env, tenantId: string, evidenceId: string, updates: { name?: string; description?: string; fileUrl?: string; fileType?: string; fileSize?: number }) {
  const fields = [];
  const values = [];
  if (updates.name !== undefined) { fields.push('name = ?'); values.push(updates.name); }
  if (updates.description !== undefined) { fields.push('description = ?'); values.push(updates.description); }
  if (updates.fileUrl !== undefined) { fields.push('file_url = ?'); values.push(updates.fileUrl); }
  if (updates.fileType !== undefined) { fields.push('file_type = ?'); values.push(updates.fileType); }
  if (updates.fileSize !== undefined) { fields.push('file_size = ?'); values.push(updates.fileSize); }
  if (fields.length === 0) return false;
  const query = `UPDATE evidence SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`;
  await env.DB.prepare(query).bind(...values, tenantId, evidenceId).run();
  return true;
}
async function attachEvidenceToControl(env: Env, controlId: string, evidenceId: string, attachedBy: string) {
  const id = crypto.randomUUID();
  await env.DB.prepare('INSERT OR IGNORE INTO control_evidence(id, control_id, evidence_id, attached_by) VALUES(?, ?, ?, ?)').bind(id, controlId, evidenceId, attachedBy).run();
  return { id };
}
async function getControlEvidence(env: Env, controlId: string) {
  return await env.DB.prepare('SELECT e.*, ce.attached_at, u.name as attached_by_name FROM control_evidence ce INNER JOIN evidence e ON ce.evidence_id = e.id LEFT JOIN users u ON ce.attached_by = u.id WHERE ce.control_id = ? ORDER BY ce.attached_at DESC').bind(controlId).all<any>();
}

// Assessment functions
async function getAssessments(env: Env, tenantId: string, controlId?: string, limit: string = '50', offset: string = '0') {
  if (controlId) {
    return await env.DB.prepare('SELECT a.*, c.code as control_code, c.title as control_title, u.name as assessor_name FROM assessments a LEFT JOIN controls c ON a.control_id = c.id LEFT JOIN users u ON a.assessor_user_id = u.id WHERE a.tenant_id = ? AND a.control_id = ? ORDER BY a.created_at DESC LIMIT ? OFFSET ?').bind(tenantId, controlId, limit, offset).all<any>();
  }
  return await env.DB.prepare('SELECT a.*, c.code as control_code, c.title as control_title, u.name as assessor_name FROM assessments a LEFT JOIN controls c ON a.control_id = c.id LEFT JOIN users u ON a.assessor_user_id = u.id WHERE a.tenant_id = ? ORDER BY a.created_at DESC LIMIT ? OFFSET ?').bind(tenantId, limit, offset).all<any>();
}
async function getAssessmentById(env: Env, tenantId: string, assessmentId: string) {
  return await env.DB.prepare('SELECT a.*, c.code as control_code, c.title as control_title, u.name as assessor_name FROM assessments a LEFT JOIN controls c ON a.control_id = c.id LEFT JOIN users u ON a.assessor_user_id = u.id WHERE a.tenant_id = ? AND a.id = ?').bind(tenantId, assessmentId).first<any>();
}
async function createAssessment(env: Env, tenantId: string, assessment: { controlId: string; assessorUserId?: string; dueDate?: string; notes?: string }) {
  const id = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO assessments(id, control_id, tenant_id, assessor_user_id, due_date, notes) VALUES(?, ?, ?, ?, ?, ?)').bind(id, assessment.controlId, tenantId, assessment.assessorUserId || null, assessment.dueDate || null, assessment.notes || '').run();
  return { id };
}
async function updateAssessment(env: Env, tenantId: string, assessmentId: string, updates: { status?: string; result?: string; notes?: string; assessorUserId?: string; assessmentDate?: string }) {
  const fields = [];
  const values = [];
  if (updates.status !== undefined) { fields.push('status = ?'); values.push(updates.status); }
  if (updates.result !== undefined) { fields.push('result = ?'); values.push(updates.result); }
  if (updates.notes !== undefined) { fields.push('notes = ?'); values.push(updates.notes); }
  if (updates.assessorUserId !== undefined) { fields.push('assessor_user_id = ?'); values.push(updates.assessorUserId); }
  if (updates.assessmentDate !== undefined) { fields.push('assessment_date = ?'); values.push(updates.assessmentDate); }
  if (fields.length === 0) return false;
  fields.push('updated_at = (strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'))');
  const query = `UPDATE assessments SET ${fields.join(', ')} WHERE tenant_id = ? AND id = ?`;
  await env.DB.prepare(query).bind(...values, tenantId, assessmentId).run();
  return true;
}

// Reporting functions
async function getComplianceReport(env: Env, tenantId: string, frameworkId?: string) {
  let query = `SELECT 
      f.name as framework_name,
      COUNT(c.id) as total_controls,
      COUNT(CASE WHEN c.status = 'completed' THEN 1 END) as completed_controls,
      COUNT(CASE WHEN c.status = 'in_progress' THEN 1 END) as in_progress_controls,
      COUNT(CASE WHEN c.status = 'not_started' THEN 1 END) as not_started_controls,
      COUNT(CASE WHEN a.result = 'pass' THEN 1 END) as passed_assessments,
      COUNT(CASE WHEN a.result = 'fail' THEN 1 END) as failed_assessments
    FROM frameworks f
    INNER JOIN tenant_frameworks tf ON f.id = tf.framework_id
    LEFT JOIN controls c ON f.id = c.framework_id AND c.tenant_id = ?
    LEFT JOIN assessments a ON c.id = a.control_id
    WHERE tf.tenant_id = ?`;
  const params = [tenantId, tenantId];
  
  if (frameworkId) {
    query += ' AND f.id = ?';
    params.push(frameworkId);
  }
  
  query += ' GROUP BY f.id, f.name ORDER BY f.name';
  
  return await env.DB.prepare(query).bind(...params).all<any>();
}
async function getTaskSummary(env: Env, tenantId: string, userId?: string) {
  let query = `SELECT 
      COUNT(*) as total_tasks,
      COUNT(CASE WHEN status = 'open' THEN 1 END) as open_tasks,
      COUNT(CASE WHEN status = 'in_progress' THEN 1 END) as in_progress_tasks,
      COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_tasks,
      COUNT(CASE WHEN due_date < date('now') AND status != 'completed' THEN 1 END) as overdue_tasks
    FROM tasks 
    WHERE tenant_id = ?`;
  const params = [tenantId];
  
  if (userId) {
    query += ' AND assigned_to = ?';
    params.push(userId);
  }
  
  return await env.DB.prepare(query).bind(...params).first<any>();
}

async function verifyTurnstile(env: Env, token?: string, ip?: string | null) {
  if (!env.TURNSTILE_SECRET_KEY) return { success: true, skipped: true };
  if (!token) return { success: false };
  try {
    const form = new URLSearchParams();
    form.set('secret', env.TURNSTILE_SECRET_KEY);
    form.set('response', token);
    if (ip) form.set('remoteip', ip);
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form,
      headers: { 'content-type': 'application/x-www-form-urlencoded' }
    });
    const out = await r.json<any>();
    return { success: Boolean(out.success), out };
  } catch {
    return { success: false };
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { path, method } = parseUrl(request);

    // CORS preflight
    if (method === 'OPTIONS') {
      const res = new Response(null, { status: 204 });
      cors(request, res.headers);
      return res;
    }

    // Domain to tenant mapping
    if (method === 'GET' && path === '/tenant/by-domain') {
      const url = new URL(request.url);
      const domain = url.searchParams.get('domain');
      if (!domain) { const r = json({ error: 'domain required' }, 400); cors(request, r.headers); return r; }
      const tId = await mapDomainToTenant(env, domain);
      const r = json({ tenantId: tId });
      cors(request, r.headers); return r;
    }

    // Invites
    if (path === '/invites') {
      if (method === 'POST') {
        const token = getCookie(request, 'c360_session');
        const sess = await verifySession(env, token);
        if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
        const body = await readJson<{ email?: string; role?: string }>(request);
        const t = await getTenantBySlug(env, sess.tenant || '');
        if (!t || !body?.email) { const r = json({ error: 'invalid' }, 400); cors(request, r.headers); return r; }
        const inv = await createInvite(env, t.id, body.email, body.role || 'team_member');
        const r = json({ ok: true, invite: inv });
        cors(request, r.headers); return r;
      }
    }

    if (path === '/invites/accept' && method === 'POST') {
      const body = await readJson<{ token?: string; name?: string; password?: string }>(request);
      if (!body?.token || !body?.name || !body?.password) { const r = json({ error: 'invalid' }, 400); cors(request, r.headers); return r; }
      const resAcc = await acceptInvite(env, body.token, body.name, body.password);
      if (!resAcc) { const r = json({ error: 'invalid_or_expired' }, 400); cors(request, r.headers); return r; }
      const slugGuess = body?.token?.slice(0, 0); // no-op; client should redirect using context
      const session = await createSession(env, { sub: resAcc.userId, email: resAcc.email }, 60 * 60 * 12);
      const r = json({ ok: true }); r.headers.append('set-cookie', toCookie(session, 60 * 60 * 12));
      cors(request, r.headers); return r;
    }

    // Password reset
    if (path === '/auth/reset/request' && method === 'POST') {
      const body = await readJson<{ email?: string }>(request);
      if (!body?.email) { const r = json({ ok: true }); cors(request, r.headers); return r; }
      // lookup user across possible tenants by domain mapping
      const domain = body.email.split('@')[1]?.toLowerCase();
      const tenantId = domain ? await mapDomainToTenant(env, domain) : null;
      if (!tenantId) { const r = json({ ok: true }); cors(request, r.headers); return r; }
      const user = await env.DB.prepare('SELECT id FROM users WHERE tenant_id = ? AND email = ?').bind(tenantId, body.email.toLowerCase()).first<any>();
      if (!user) { const r = json({ ok: true }); cors(request, r.headers); return r; }
      const token = crypto.randomUUID();
      const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      await env.DB.prepare('INSERT INTO password_reset_tokens(id, user_id, token, expires_at) VALUES(?, ?, ?, ?)').bind(crypto.randomUUID(), user.id, token, expires).run();
      // In production, send email via Queues
      const r = json({ ok: true, token }); cors(request, r.headers); return r;
    }

    if (path === '/auth/reset/confirm' && method === 'POST') {
      const body = await readJson<{ token?: string; password?: string }>(request);
      if (!body?.token || !body?.password) { const r = json({ error: 'invalid' }, 400); cors(request, r.headers); return r; }
      const prt = await env.DB.prepare('SELECT * FROM password_reset_tokens WHERE token = ? AND used = 0 AND expires_at > (strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'))').bind(body.token).first<any>();
      if (!prt) { const r = json({ error: 'invalid_or_expired' }, 400); cors(request, r.headers); return r; }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iter = 100_000;
      const hash = await pbkdf2(body.password, salt, iter);
      await env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ?, password_iter = ? WHERE id = ?').bind(hex(hash), hex(salt), iter, prt.user_id).run();
      await env.DB.prepare('UPDATE password_reset_tokens SET used = 1 WHERE id = ?').bind(prt.id).run();
      const r = json({ ok: true }); cors(request, r.headers); return r;
    }

    if (path === '/auth/login/recovery' && method === 'POST') {
      const body = await readJson<{ email?: string; code?: string }>(request);
      if (!body?.email || !body?.code) { const r = json({ error: 'invalid' }, 400); cors(request, r.headers); return r; }
      const domain = body.email.split('@')[1]?.toLowerCase();
      const tenantId = domain ? await mapDomainToTenant(env, domain) : null;
      if (!tenantId) { const r = json({ error: 'invalid' }, 400); cors(request, r.headers); return r; }
      const user = await env.DB.prepare('SELECT * FROM users WHERE tenant_id = ? AND email = ?').bind(tenantId, body.email.toLowerCase()).first<any>();
      if (!user) { const r = json({ error: 'invalid' }, 400); cors(request, r.headers); return r; }
      const ok = await consumeRecoveryCode(env, user.id, body.code);
      if (!ok) { const r = json({ error: 'invalid_code' }, 400); cors(request, r.headers); return r; }
      const token = await createSession(env, { sub: user.id, email: user.email }, 60 * 60 * 12);
      const r = json({ ok: true }); r.headers.append('set-cookie', toCookie(token, 60 * 60 * 12)); cors(request, r.headers); return r;
    }

    // Admin: set domain mapping (protect behind Access in production)
    if (path === '/admin/domains' && method === 'POST') {
      const body = await readJson<{ domain?: string; tenant?: string }>(request);
      if (!body?.domain || !body?.tenant) { const r = json({ error: 'invalid' }, 400); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, body.tenant);
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      await setDomainMapping(env, body.domain, t.id);
      const r = json({ ok: true }); cors(request, r.headers); return r;
    }
    // Health checks
    if (method === 'GET' && (path === '/health' || path === '/status' || path === '/healthz')) {
      const res = json({ ok: true, service: 'api', ts: Date.now() });
      cors(request, res.headers);
      return res;
    }

    // Session: whoami
    if (method === 'GET' && path === '/auth/me') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      const res = json({ authenticated: Boolean(sess), user: sess ?? null });
      cors(request, res.headers);
      return res;
    }

    // Simple CSRF check for POST endpoints (dev-friendly)
    if (method === 'POST') {
      const csrf = request.headers.get('x-csrf');
      if (!csrf) { const r = json({ error: 'csrf_required' }, 400); cors(request, r.headers); return r; }
    }

    // Signup
    if (method === 'POST' && path === '/auth/signup') {
      const body = await readJson<{ email?: string; name?: string; company?: string; password?: string; tenant?: string; cfTurnstileToken?: string }>(request);
      if (!body?.email) {
        const res = json({ error: 'email required' }, 400);
        cors(request, res.headers);
        return res;
      }
      const verify = await verifyTurnstile(env, body?.cfTurnstileToken, request.headers.get('cf-connecting-ip'));
      if (!verify.success) {
        const res = json({ error: 'turnstile_failed' }, 400);
        cors(request, res.headers);
        return res;
      }
  const slug = (body.tenant || body.company || body.email.split('@')[1]?.split('.')[0] || 'org').toLowerCase().replace(/[^a-z0-9-]/g,'-');
  const { id: tenantId } = await ensureTenant(env, slug, body.company || slug);
  const pwd = body.password || crypto.randomUUID();
  const { id: userId } = await insertUser(env, tenantId, body.email.toLowerCase(), body.name || 'User', pwd);
  const token = await createSession(env, { sub: userId, email: body.email.toLowerCase(), tenant: slug }, 60 * 60 * 12);
  const res = json({ ok: true, tenant: slug });
  res.headers.append('set-cookie', toCookie(token, 60 * 60 * 12));
  cors(request, res.headers);
  return res;
    }

    // Login
    if (method === 'POST' && path === '/auth/login') {
      const body = await readJson<{ email?: string; password?: string; totp?: string; cfTurnstileToken?: string }>(request);
      if (!body?.email) {
        const res = json({ error: 'email required' }, 400);
        cors(request, res.headers);
        return res;
      }
      const verify = await verifyTurnstile(env, body?.cfTurnstileToken, request.headers.get('cf-connecting-ip'));
      if (!verify.success) {
        const res = json({ error: 'turnstile_failed' }, 400);
        cors(request, res.headers);
        return res;
      }
      const slug = body.email.split('@')[1]?.split('.')[0] || 'org';
      const t = await getTenantBySlug(env, slug) || await ensureTenant(env, slug, slug);
      const user = await getUserByEmail(env, t.id, body.email.toLowerCase());
      if (!user) {
        const res = json({ error: 'invalid_credentials' }, 401);
        cors(request, res.headers);
        return res;
      }
  const salt = fromHex(user.password_salt);
      const calc = await pbkdf2(body.password || '', salt, user.password_iter, 32);
      if (hex(calc) !== user.password_hash) {
        const res = json({ error: 'invalid_credentials' }, 401);
        cors(request, res.headers);
        return res;
      }
      if (user.mfa_enabled) {
        if (!body.totp || !user.mfa_secret) {
          const res = json({ error: 'totp_required' }, 401);
          cors(request, res.headers);
          return res;
        }
        const secretBytes = decodeBase32(user.mfa_secret);
        const code = await totp(secretBytes);
        if (code !== body.totp) {
          const res = json({ error: 'invalid_totp' }, 401);
          cors(request, res.headers);
          return res;
        }
      }
      const token = await createSession(env, { sub: user.id, email: user.email, tenant: slug }, 60 * 60 * 12);
      const res = json({ ok: true, tenant: slug });
      res.headers.append('set-cookie', toCookie(token, 60 * 60 * 12));
      cors(request, res.headers);
      return res;
    }

    // Logout
    if (method === 'POST' && path === '/auth/logout') {
      const res = json({ ok: true });
      // Expire cookie
      res.headers.append('set-cookie', `c360_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
      cors(request, res.headers);
      return res;
    }

    // MFA setup (return otpauth URL)
    if (method === 'POST' && path === '/auth/mfa/setup') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const secret = crypto.getRandomValues(new Uint8Array(20));
      const base32 = btoa(String.fromCharCode(...secret)).replace(/=/g,'').replace(/[+/]/g, 'A');
      await setUserMfa(env, sess.sub, base32);
      const url = `otpauth://totp/Comp360Flow:${encodeURIComponent(sess.email)}?secret=${base32}&issuer=Comp360Flow`;
      const r = json({ ok: true, otpauth: url });
      cors(request, r.headers);
      return r;
    }

    // Branding (GET/PUT)
    if (path === '/branding') {
      if (method === 'GET') {
        const url = new URL(request.url);
        const tenantSlug = url.searchParams.get('tenant');
        if (!tenantSlug) { const r = json({ error: 'tenant required' }, 400); cors(request, r.headers); return r; }
        const t = await getTenantBySlug(env, tenantSlug);
        if (!t) { const r = json({ error: 'not_found' }, 404); cors(request, r.headers); return r; }
  const keyReq = new Request(`https://cache.c360.local/brand/${tenantSlug}`);
  const defaultCache = (caches as any).default as Cache;
  let cached = defaultCache ? await defaultCache.match(keyReq) : undefined;
  if (cached) { const r = new Response(await cached.clone().arrayBuffer(), cached); cors(request, r.headers); return r; }
        const brand = await getBranding(env, t.id);
        const res = json({ tenant: tenantSlug, brand });
        cors(request, res.headers);
        res.headers.set('Cache-Control', 'public, max-age=60');
  if (defaultCache) await defaultCache.put(keyReq, res.clone());
        return res;
      }
      if (method === 'PUT') {
        const token = getCookie(request, 'c360_session');
        const sess = await verifySession(env, token);
        if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
        const body = await readJson<{ logoText?: string; primary?: string; secondary?: string }>(request);
        const t = await getTenantBySlug(env, sess.tenant || '');
        if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
  await setBranding(env, t.id, body?.logoText || 'Comp360Flow', body?.primary || '#0b62d6', body?.secondary || '#eef6ff');
  const defaultCache2 = (caches as any).default as Cache;
  if (defaultCache2 && sess.tenant) await defaultCache2.delete(new Request(`https://cache.c360.local/brand/${sess.tenant}`));
        const r = json({ ok: true });
        cors(request, r.headers);
        return r;
      }
    }

    // User Management APIs
    if (path === '/users' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const url = new URL(request.url);
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0'), 0);
      
      const users = await listUsers(env, t.id, limit.toString(), offset.toString());
      const r = json({ users: users.results, count: users.results.length });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/users/') && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const userId = path.split('/')[2];
      if (!userId) { const r = json({ error: 'user_id_required' }, 400); cors(request, r.headers); return r; }
      
      const user = await getUserById(env, t.id, userId);
      if (!user) { const r = json({ error: 'user_not_found' }, 404); cors(request, r.headers); return r; }
      
      // Remove sensitive fields
      const { password_hash, password_salt, password_iter, mfa_secret, ...safeUser } = user;
      const r = json({ user: safeUser });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/users/') && method === 'PUT') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const userId = path.split('/')[2];
      if (!userId) { const r = json({ error: 'user_id_required' }, 400); cors(request, r.headers); return r; }
      
      const body = await readJson<{ name?: string; role?: string; status?: string }>(request);
      if (!body) { const r = json({ error: 'invalid_body' }, 400); cors(request, r.headers); return r; }
      
      // Validate role if provided
      if (body.role && !['company_admin', 'compliance_manager', 'team_member', 'auditor'].includes(body.role)) {
        const r = json({ error: 'invalid_role' }, 400); cors(request, r.headers); return r;
      }
      
      // Validate status if provided
      if (body.status && !['active', 'inactive', 'pending'].includes(body.status)) {
        const r = json({ error: 'invalid_status' }, 400); cors(request, r.headers); return r;
      }
      
      const updated = await updateUser(env, t.id, userId, body);
      if (!updated) { const r = json({ error: 'user_not_found' }, 404); cors(request, r.headers); return r; }
      
      const r = json({ ok: true });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/users/') && path.endsWith('/deactivate') && method === 'POST') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const userId = path.split('/')[2];
      if (!userId) { const r = json({ error: 'user_id_required' }, 400); cors(request, r.headers); return r; }
      
      // Don't allow users to deactivate themselves
      if (userId === sess.sub) { const r = json({ error: 'cannot_deactivate_self' }, 400); cors(request, r.headers); return r; }
      
      const deactivated = await deactivateUser(env, t.id, userId);
      if (!deactivated) { const r = json({ error: 'user_not_found' }, 404); cors(request, r.headers); return r; }
      
      const r = json({ ok: true });
      cors(request, r.headers);
      return r;
    }

    // Tenant Management APIs
    if (path === '/tenant' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const settings = await getTenantSettings(env, t.id);
      const branding = await getBranding(env, t.id);
      const r = json({ tenant: { ...settings, branding } });
      cors(request, r.headers);
      return r;
    }

    if (path === '/tenant' && method === 'PUT') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const body = await readJson<{ name?: string; plan?: string }>(request);
      if (!body) { const r = json({ error: 'invalid_body' }, 400); cors(request, r.headers); return r; }
      
      // Validate plan if provided
      if (body.plan && !['starter', 'professional', 'enterprise'].includes(body.plan)) {
        const r = json({ error: 'invalid_plan' }, 400); cors(request, r.headers); return r;
      }
      
      const updated = await updateTenant(env, t.id, body);
      if (!updated) { const r = json({ error: 'nothing_to_update' }, 400); cors(request, r.headers); return r; }
      
      const r = json({ ok: true });
      cors(request, r.headers);
      return r;
    }

    if (path === '/tenant/users' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const url = new URL(request.url);
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0'), 0);
      
      const users = await listUsers(env, t.id, limit.toString(), offset.toString());
      const r = json({ users: users.results, count: users.results.length });
      cors(request, r.headers);
      return r;
    }

    // Audit Log APIs
    if (path === '/audit' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const url = new URL(request.url);
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0'), 0);
      
      const logs = await getAuditLogs(env, t.id, limit.toString(), offset.toString());
      const r = json({ logs: logs.results, count: logs.results.length });
      cors(request, r.headers);
      return r;
    }

    // Compliance Framework APIs
    if (path === '/frameworks' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      
      const frameworks = await getFrameworks(env);
      const r = json({ frameworks: frameworks.results });
      cors(request, r.headers);
      return r;
    }

    if (path === '/tenant/frameworks' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const frameworks = await getTenantFrameworks(env, t.id);
      const r = json({ frameworks: frameworks.results });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/frameworks/') && path.endsWith('/enable') && method === 'POST') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const frameworkId = path.split('/')[2];
      if (!frameworkId) { const r = json({ error: 'framework_id_required' }, 400); cors(request, r.headers); return r; }
      
      await enableFrameworkForTenant(env, t.id, frameworkId);
      await createAuditLog(env, t.id, sess.sub, 'framework_enabled', frameworkId);
      
      const r = json({ ok: true });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/frameworks/') && path.endsWith('/disable') && method === 'POST') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const frameworkId = path.split('/')[2];
      if (!frameworkId) { const r = json({ error: 'framework_id_required' }, 400); cors(request, r.headers); return r; }
      
      await disableFrameworkForTenant(env, t.id, frameworkId);
      await createAuditLog(env, t.id, sess.sub, 'framework_disabled', frameworkId);
      
      const r = json({ ok: true });
      cors(request, r.headers);
      return r;
    }

    // Control Management APIs
    if (path === '/controls' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const url = new URL(request.url);
      const frameworkId = url.searchParams.get('framework');
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0'), 0);
      
      const controls = await getControls(env, t.id, frameworkId || undefined, limit.toString(), offset.toString());
      const r = json({ controls: controls.results, count: controls.results.length });
      cors(request, r.headers);
      return r;
    }

    if (path === '/controls' && method === 'POST') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const body = await readJson<{ frameworkId?: string; code?: string; title?: string; description?: string; controlType?: string; frequency?: string; ownerUserId?: string }>(request);
      if (!body?.code || !body?.title) { const r = json({ error: 'code_and_title_required' }, 400); cors(request, r.headers); return r; }
      
      // Validate frequency
      if (body.frequency && !['daily', 'weekly', 'monthly', 'quarterly', 'annual'].includes(body.frequency)) {
        const r = json({ error: 'invalid_frequency' }, 400); cors(request, r.headers); return r;
      }
      
      // Validate control type
      if (body.controlType && !['manual', 'automated', 'hybrid'].includes(body.controlType)) {
        const r = json({ error: 'invalid_control_type' }, 400); cors(request, r.headers); return r;
      }
      
      const control = await createControl(env, t.id, {
        frameworkId: body.frameworkId,
        code: body.code,
        title: body.title,
        description: body.description,
        controlType: body.controlType,
        frequency: body.frequency,
        ownerUserId: body.ownerUserId
      });
      await createAuditLog(env, t.id, sess.sub, 'control_created', control.id, { code: body.code, title: body.title });
      
      const r = json({ ok: true, control });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/controls/') && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const controlId = path.split('/')[2];
      if (!controlId) { const r = json({ error: 'control_id_required' }, 400); cors(request, r.headers); return r; }
      
      const control = await getControlById(env, t.id, controlId);
      if (!control) { const r = json({ error: 'control_not_found' }, 404); cors(request, r.headers); return r; }
      
      const r = json({ control });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/controls/') && method === 'PUT') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const controlId = path.split('/')[2];
      if (!controlId) { const r = json({ error: 'control_id_required' }, 400); cors(request, r.headers); return r; }
      
      const body = await readJson<{ title?: string; description?: string; controlType?: string; frequency?: string; ownerUserId?: string; status?: string }>(request);
      if (!body) { const r = json({ error: 'invalid_body' }, 400); cors(request, r.headers); return r; }
      
      // Validate frequency
      if (body.frequency && !['daily', 'weekly', 'monthly', 'quarterly', 'annual'].includes(body.frequency)) {
        const r = json({ error: 'invalid_frequency' }, 400); cors(request, r.headers); return r;
      }
      
      // Validate control type
      if (body.controlType && !['manual', 'automated', 'hybrid'].includes(body.controlType)) {
        const r = json({ error: 'invalid_control_type' }, 400); cors(request, r.headers); return r;
      }
      
      // Validate status
      if (body.status && !['not_started', 'in_progress', 'under_review', 'completed', 'failed'].includes(body.status)) {
        const r = json({ error: 'invalid_status' }, 400); cors(request, r.headers); return r;
      }
      
      const updated = await updateControl(env, t.id, controlId, body);
      if (!updated) { const r = json({ error: 'control_not_found' }, 404); cors(request, r.headers); return r; }
      
      await createAuditLog(env, t.id, sess.sub, 'control_updated', controlId);
      
      const r = json({ ok: true });
      cors(request, r.headers);
      return r;
    }

    // Task Management APIs
    if (path === '/tasks' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const url = new URL(request.url);
      const assignedTo = url.searchParams.get('assigned_to') || undefined;
      const project = url.searchParams.get('project') || undefined;
      const status = url.searchParams.get('status') || undefined;
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0'), 0);
      
      const tasks = await getTasks(env, t.id, { assignedTo, project, status }, limit, offset);
      const r = json({ tasks: tasks.results, count: tasks.results.length });
      cors(request, r.headers);
      return r;
    }

    if (path === '/tasks' && method === 'POST') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const body = await readJson<{ title?: string; description?: string; projectId?: string; controlId?: string; assignedTo?: string; priority?: string; dueDate?: string }>(request);
      if (!body?.title) { const r = json({ error: 'title_required' }, 400); cors(request, r.headers); return r; }
      
      // Validate priority
      if (body.priority && !['low', 'medium', 'high', 'critical'].includes(body.priority)) {
        const r = json({ error: 'invalid_priority' }, 400); cors(request, r.headers); return r;
      }
      
      const task = await createTask(env, t.id, {
        title: body.title,
        description: body.description,
        projectId: body.projectId,
        controlId: body.controlId,
        assignedTo: body.assignedTo,
        priority: body.priority,
        dueDate: body.dueDate
      }, sess.sub);
      
      await createAuditLog(env, t.id, sess.sub, 'task_created', task.id, { title: body.title });
      
      const r = json({ ok: true, task });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/tasks/') && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const taskId = path.split('/')[2];
      if (!taskId) { const r = json({ error: 'task_id_required' }, 400); cors(request, r.headers); return r; }
      
      const task = await getTaskById(env, t.id, taskId);
      if (!task) { const r = json({ error: 'task_not_found' }, 404); cors(request, r.headers); return r; }
      
      const r = json({ task });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/tasks/') && method === 'PUT') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const taskId = path.split('/')[2];
      if (!taskId) { const r = json({ error: 'task_id_required' }, 400); cors(request, r.headers); return r; }
      
      const body = await readJson<{ title?: string; description?: string; status?: string; priority?: string; assignedTo?: string; dueDate?: string }>(request);
      if (!body) { const r = json({ error: 'invalid_body' }, 400); cors(request, r.headers); return r; }
      
      // Validate status
      if (body.status && !['open', 'in_progress', 'completed', 'cancelled'].includes(body.status)) {
        const r = json({ error: 'invalid_status' }, 400); cors(request, r.headers); return r;
      }
      
      // Validate priority
      if (body.priority && !['low', 'medium', 'high', 'critical'].includes(body.priority)) {
        const r = json({ error: 'invalid_priority' }, 400); cors(request, r.headers); return r;
      }
      
      const updated = await updateTask(env, t.id, taskId, body);
      if (!updated) { const r = json({ error: 'task_not_found' }, 404); cors(request, r.headers); return r; }
      
      await createAuditLog(env, t.id, sess.sub, 'task_updated', taskId);
      
      const r = json({ ok: true });
      cors(request, r.headers);
      return r;
    }

    // Project Management APIs
    if (path === '/projects' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const url = new URL(request.url);
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0'), 0);
      
      const projects = await getProjects(env, t.id, limit.toString(), offset.toString());
      const r = json({ projects: projects.results, count: projects.results.length });
      cors(request, r.headers);
      return r;
    }

    if (path === '/projects' && method === 'POST') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const body = await readJson<{ name?: string; description?: string; managerUserId?: string; startDate?: string; endDate?: string }>(request);
      if (!body?.name) { const r = json({ error: 'name_required' }, 400); cors(request, r.headers); return r; }
      
      const project = await createProject(env, t.id, {
        name: body.name,
        description: body.description,
        managerUserId: body.managerUserId,
        startDate: body.startDate,
        endDate: body.endDate
      });
      
      await createAuditLog(env, t.id, sess.sub, 'project_created', project.id, { name: body.name });
      
      const r = json({ ok: true, project });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/projects/') && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const projectId = path.split('/')[2];
      if (!projectId) { const r = json({ error: 'project_id_required' }, 400); cors(request, r.headers); return r; }
      
      const project = await getProjectById(env, t.id, projectId);
      if (!project) { const r = json({ error: 'project_not_found' }, 404); cors(request, r.headers); return r; }
      
      const r = json({ project });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/projects/') && method === 'PUT') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const projectId = path.split('/')[2];
      if (!projectId) { const r = json({ error: 'project_id_required' }, 400); cors(request, r.headers); return r; }
      
      const body = await readJson<{ name?: string; description?: string; status?: string; managerUserId?: string; startDate?: string; endDate?: string }>(request);
      if (!body) { const r = json({ error: 'invalid_body' }, 400); cors(request, r.headers); return r; }
      
      // Validate status
      if (body.status && !['active', 'completed', 'on_hold', 'cancelled'].includes(body.status)) {
        const r = json({ error: 'invalid_status' }, 400); cors(request, r.headers); return r;
      }
      
      const updated = await updateProject(env, t.id, projectId, body);
      if (!updated) { const r = json({ error: 'project_not_found' }, 404); cors(request, r.headers); return r; }
      
      await createAuditLog(env, t.id, sess.sub, 'project_updated', projectId);
      
      const r = json({ ok: true });
      cors(request, r.headers);
      return r;
    }

    // Evidence Management APIs
    if (path === '/evidence' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const url = new URL(request.url);
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0'), 0);
      
      const evidence = await getEvidence(env, t.id, limit.toString(), offset.toString());
      const r = json({ evidence: evidence.results, count: evidence.results.length });
      cors(request, r.headers);
      return r;
    }

    if (path === '/evidence' && method === 'POST') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const body = await readJson<{ name?: string; description?: string; fileUrl?: string; fileType?: string; fileSize?: number }>(request);
      if (!body?.name) { const r = json({ error: 'name_required' }, 400); cors(request, r.headers); return r; }
      
      const evidence = await createEvidence(env, t.id, {
        name: body.name,
        description: body.description,
        fileUrl: body.fileUrl,
        fileType: body.fileType,
        fileSize: body.fileSize
      }, sess.sub);
      
      await createAuditLog(env, t.id, sess.sub, 'evidence_created', evidence.id, { name: body.name });
      
      const r = json({ ok: true, evidence });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/evidence/') && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const evidenceId = path.split('/')[2];
      if (!evidenceId) { const r = json({ error: 'evidence_id_required' }, 400); cors(request, r.headers); return r; }
      
      const evidence = await getEvidenceById(env, t.id, evidenceId);
      if (!evidence) { const r = json({ error: 'evidence_not_found' }, 404); cors(request, r.headers); return r; }
      
      const r = json({ evidence });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/evidence/') && method === 'PUT') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const evidenceId = path.split('/')[2];
      if (!evidenceId) { const r = json({ error: 'evidence_id_required' }, 400); cors(request, r.headers); return r; }
      
      const body = await readJson<{ name?: string; description?: string; fileUrl?: string; fileType?: string; fileSize?: number }>(request);
      if (!body) { const r = json({ error: 'invalid_body' }, 400); cors(request, r.headers); return r; }
      
      const updated = await updateEvidence(env, t.id, evidenceId, body);
      if (!updated) { const r = json({ error: 'evidence_not_found' }, 404); cors(request, r.headers); return r; }
      
      await createAuditLog(env, t.id, sess.sub, 'evidence_updated', evidenceId);
      
      const r = json({ ok: true });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/evidence/') && path.endsWith('/attach') && method === 'POST') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const evidenceId = path.split('/')[2];
      if (!evidenceId) { const r = json({ error: 'evidence_id_required' }, 400); cors(request, r.headers); return r; }
      
      const body = await readJson<{ controlId?: string }>(request);
      if (!body?.controlId) { const r = json({ error: 'control_id_required' }, 400); cors(request, r.headers); return r; }
      
      const attachment = await attachEvidenceToControl(env, body.controlId, evidenceId, sess.sub);
      await createAuditLog(env, t.id, sess.sub, 'evidence_attached', evidenceId, { controlId: body.controlId });
      
      const r = json({ ok: true, attachment });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/controls/') && path.endsWith('/evidence') && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const controlId = path.split('/')[2];
      if (!controlId) { const r = json({ error: 'control_id_required' }, 400); cors(request, r.headers); return r; }
      
      const evidence = await getControlEvidence(env, controlId);
      const r = json({ evidence: evidence.results });
      cors(request, r.headers);
      return r;
    }

    // Assessment APIs
    if (path === '/assessments' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const url = new URL(request.url);
      const controlId = url.searchParams.get('control') || undefined;
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0'), 0);
      
      const assessments = await getAssessments(env, t.id, controlId, limit.toString(), offset.toString());
      const r = json({ assessments: assessments.results, count: assessments.results.length });
      cors(request, r.headers);
      return r;
    }

    if (path === '/assessments' && method === 'POST') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const body = await readJson<{ controlId?: string; assessorUserId?: string; dueDate?: string; notes?: string }>(request);
      if (!body?.controlId) { const r = json({ error: 'control_id_required' }, 400); cors(request, r.headers); return r; }
      
      const assessment = await createAssessment(env, t.id, {
        controlId: body.controlId,
        assessorUserId: body.assessorUserId,
        dueDate: body.dueDate,
        notes: body.notes
      });
      
      await createAuditLog(env, t.id, sess.sub, 'assessment_created', assessment.id, { controlId: body.controlId });
      
      const r = json({ ok: true, assessment });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/assessments/') && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const assessmentId = path.split('/')[2];
      if (!assessmentId) { const r = json({ error: 'assessment_id_required' }, 400); cors(request, r.headers); return r; }
      
      const assessment = await getAssessmentById(env, t.id, assessmentId);
      if (!assessment) { const r = json({ error: 'assessment_not_found' }, 404); cors(request, r.headers); return r; }
      
      const r = json({ assessment });
      cors(request, r.headers);
      return r;
    }

    if (path.startsWith('/assessments/') && method === 'PUT') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const assessmentId = path.split('/')[2];
      if (!assessmentId) { const r = json({ error: 'assessment_id_required' }, 400); cors(request, r.headers); return r; }
      
      const body = await readJson<{ status?: string; result?: string; notes?: string; assessorUserId?: string; assessmentDate?: string }>(request);
      if (!body) { const r = json({ error: 'invalid_body' }, 400); cors(request, r.headers); return r; }
      
      // Validate status
      if (body.status && !['planned', 'in_progress', 'completed', 'failed'].includes(body.status)) {
        const r = json({ error: 'invalid_status' }, 400); cors(request, r.headers); return r;
      }
      
      // Validate result
      if (body.result && !['pass', 'fail', 'na', 'partial'].includes(body.result)) {
        const r = json({ error: 'invalid_result' }, 400); cors(request, r.headers); return r;
      }
      
      const updated = await updateAssessment(env, t.id, assessmentId, body);
      if (!updated) { const r = json({ error: 'assessment_not_found' }, 404); cors(request, r.headers); return r; }
      
      await createAuditLog(env, t.id, sess.sub, 'assessment_updated', assessmentId);
      
      const r = json({ ok: true });
      cors(request, r.headers);
      return r;
    }

    // Reporting APIs
    if (path === '/reports/compliance' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const url = new URL(request.url);
      const frameworkId = url.searchParams.get('framework') || undefined;
      
      const report = await getComplianceReport(env, t.id, frameworkId);
      const r = json({ report: report.results });
      cors(request, r.headers);
      return r;
    }

    if (path === '/reports/tasks' && method === 'GET') {
      const token = getCookie(request, 'c360_session');
      const sess = await verifySession(env, token);
      if (!sess) { const r = json({ error: 'unauthorized' }, 401); cors(request, r.headers); return r; }
      const t = await getTenantBySlug(env, sess.tenant || '');
      if (!t) { const r = json({ error: 'tenant_not_found' }, 404); cors(request, r.headers); return r; }
      
      const url = new URL(request.url);
      const userId = url.searchParams.get('user') || undefined;
      
      const summary = await getTaskSummary(env, t.id, userId);
      const r = json({ summary });
      cors(request, r.headers);
      return r;
    }

    const res = text('Not Found', 404);
    cors(request, res.headers);
    return res;
  }
};
