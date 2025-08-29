type Env = {
  SESSION_SECRET: string;
  TURNSTILE_SECRET_KEY?: string;
  // Microsoft 365 OAuth configuration
  M365_CLIENT_ID?: string;
  M365_CLIENT_SECRET?: string;
  M365_REDIRECT_URI?: string;
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

// Microsoft 365 OAuth and tenant integration functions
async function getM365TenantMapping(env: Env, tenantId: string) {
  return await env.DB.prepare('SELECT * FROM m365_tenant_mapping WHERE tenant_id = ?').bind(tenantId).first<any>();
}

async function setM365TenantMapping(env: Env, tenantId: string, m365TenantId: string, m365TenantDomain: string) {
  await env.DB.prepare(`
    INSERT INTO m365_tenant_mapping(tenant_id, m365_tenant_id, m365_tenant_domain) 
    VALUES(?, ?, ?) 
    ON CONFLICT(tenant_id) DO UPDATE SET 
      m365_tenant_id=excluded.m365_tenant_id, 
      m365_tenant_domain=excluded.m365_tenant_domain,
      updated_at=(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  `).bind(tenantId, m365TenantId, m365TenantDomain).run();
}

async function getM365User(env: Env, m365ObjectId: string, m365TenantId: string) {
  return await env.DB.prepare('SELECT * FROM m365_users WHERE m365_object_id = ? AND m365_tenant_id = ?').bind(m365ObjectId, m365TenantId).first<any>();
}

async function createM365User(env: Env, userId: string, m365ObjectId: string, m365Email: string, m365TenantId: string) {
  const id = crypto.randomUUID();
  await env.DB.prepare(`
    INSERT INTO m365_users(id, user_id, m365_object_id, m365_email, m365_tenant_id, last_login_at) 
    VALUES(?, ?, ?, ?, ?, (strftime('%Y-%m-%dT%H:%M:%fZ','now')))
  `).bind(id, userId, m365ObjectId, m365Email, m365TenantId).run();
  return { id };
}

async function updateM365UserLogin(env: Env, m365UserId: string) {
  await env.DB.prepare('UPDATE m365_users SET last_login_at = (strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\')) WHERE id = ?').bind(m365UserId).run();
}

async function exchangeM365Code(env: Env, code: string, state: string): Promise<{ 
  accessToken: string; 
  idToken: string; 
  userInfo: any; 
  tenantId: string;
} | null> {
  if (!env.M365_CLIENT_ID || !env.M365_CLIENT_SECRET || !env.M365_REDIRECT_URI) {
    return null;
  }

  try {
    // Exchange authorization code for tokens
    const tokenResponse = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: env.M365_CLIENT_ID,
        client_secret: env.M365_CLIENT_SECRET,
        code,
        grant_type: 'authorization_code',
        redirect_uri: env.M365_REDIRECT_URI,
        scope: 'openid profile email User.Read',
      }),
    });

    if (!tokenResponse.ok) {
      return null;
    }

    const tokens = await tokenResponse.json<any>();
    
    // Get user information using access token
    const userResponse = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: {
        'Authorization': `Bearer ${tokens.access_token}`,
      },
    });

    if (!userResponse.ok) {
      return null;
    }

    const userInfo = await userResponse.json<any>();
    
    return {
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      userInfo,
      tenantId: userInfo.id?.split('@')[1] || '', // Extract tenant from user principal name
    };
  } catch (error) {
    return null;
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

    // Microsoft 365 OAuth endpoints
    if (path === '/auth/m365/authorize' && method === 'GET') {
      if (!env.M365_CLIENT_ID || !env.M365_REDIRECT_URI) {
        const r = json({ error: 'M365 OAuth not configured' }, 500);
        cors(request, r.headers);
        return r;
      }
      
      const url = new URL(request.url);
      const tenantSlug = url.searchParams.get('tenant');
      if (!tenantSlug) {
        const r = json({ error: 'tenant required' }, 400);
        cors(request, r.headers);
        return r;
      }

      const state = `${tenantSlug}:${crypto.randomUUID()}`;
      const authUrl = new URL('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
      authUrl.searchParams.set('client_id', env.M365_CLIENT_ID);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('redirect_uri', env.M365_REDIRECT_URI);
      authUrl.searchParams.set('scope', 'openid profile email User.Read');
      authUrl.searchParams.set('state', state);

      const r = json({ 
        authorizeUrl: authUrl.toString(),
        state 
      });
      cors(request, r.headers);
      return r;
    }

    if (path === '/auth/m365/callback' && method === 'POST') {
      const body = await readJson<{ code?: string; state?: string }>(request);
      if (!body?.code || !body?.state) {
        const r = json({ error: 'invalid request' }, 400);
        cors(request, r.headers);
        return r;
      }

      const [tenantSlug] = body.state.split(':');
      if (!tenantSlug) {
        const r = json({ error: 'invalid state' }, 400);
        cors(request, r.headers);
        return r;
      }

      const tenant = await getTenantBySlug(env, tenantSlug);
      if (!tenant) {
        const r = json({ error: 'tenant not found' }, 404);
        cors(request, r.headers);
        return r;
      }

      const oauthResult = await exchangeM365Code(env, body.code, body.state);
      if (!oauthResult) {
        const r = json({ error: 'OAuth exchange failed' }, 400);
        cors(request, r.headers);
        return r;
      }

      const { userInfo } = oauthResult;
      const email = userInfo.mail || userInfo.userPrincipalName;
      const m365ObjectId = userInfo.id;
      const m365TenantId = userInfo.id?.split('@')[1] || '';

      if (!email || !m365ObjectId) {
        const r = json({ error: 'invalid user info from M365' }, 400);
        cors(request, r.headers);
        return r;
      }

      // Check if M365 tenant mapping exists and is configured for this tenant
      const m365Mapping = await getM365TenantMapping(env, tenant.id);
      if (!m365Mapping) {
        const r = json({ error: 'M365 integration not configured for this tenant' }, 400);
        cors(request, r.headers);
        return r;
      }

      // Verify the M365 tenant matches the configured one
      if (m365Mapping.m365_tenant_id !== m365TenantId) {
        const r = json({ error: 'M365 tenant mismatch' }, 403);
        cors(request, r.headers);
        return r;
      }

      // Check if user already exists in M365 mapping
      let m365User = await getM365User(env, m365ObjectId, m365TenantId);
      let userId: string;

      if (m365User) {
        // Update last login
        await updateM365UserLogin(env, m365User.id);
        userId = m365User.user_id;
      } else if (m365Mapping.auto_provision) {
        // Auto-provision user if enabled
        const existingUser = await getUserByEmail(env, tenant.id, email.toLowerCase());
        
        if (existingUser) {
          // Link existing user to M365
          userId = existingUser.id;
          await createM365User(env, userId, m365ObjectId, email, m365TenantId);
        } else {
          // Create new user
          const tempPassword = crypto.randomUUID();
          const newUser = await insertUser(env, tenant.id, email.toLowerCase(), userInfo.displayName || 'User', tempPassword);
          userId = newUser.id;
          await createM365User(env, userId, m365ObjectId, email, m365TenantId);
        }
      } else {
        const r = json({ error: 'user not found and auto-provisioning disabled' }, 403);
        cors(request, r.headers);
        return r;
      }

      // Create session
      const session = await createSession(env, { 
        sub: userId, 
        email: email.toLowerCase(), 
        tenant: tenantSlug 
      }, 60 * 60 * 12);

      const r = json({ ok: true, tenant: tenantSlug });
      r.headers.append('set-cookie', toCookie(session, 60 * 60 * 12));
      cors(request, r.headers);
      return r;
    }

    // M365 tenant configuration endpoints (admin only)
    if (path === '/admin/m365/configure' && method === 'POST') {
      const body = await readJson<{ 
        tenantSlug?: string; 
        m365TenantId?: string; 
        m365TenantDomain?: string;
        oauthEnabled?: boolean;
        autoProvision?: boolean;
      }>(request);
      
      if (!body?.tenantSlug || !body?.m365TenantId || !body?.m365TenantDomain) {
        const r = json({ error: 'missing required fields' }, 400);
        cors(request, r.headers);
        return r;
      }

      const tenant = await getTenantBySlug(env, body.tenantSlug);
      if (!tenant) {
        const r = json({ error: 'tenant not found' }, 404);
        cors(request, r.headers);
        return r;
      }

      await setM365TenantMapping(env, tenant.id, body.m365TenantId, body.m365TenantDomain);
      
      const r = json({ ok: true });
      cors(request, r.headers);
      return r;
    }

    if (path === '/admin/m365/status' && method === 'GET') {
      const url = new URL(request.url);
      const tenantSlug = url.searchParams.get('tenant');
      
      if (!tenantSlug) {
        const r = json({ error: 'tenant required' }, 400);
        cors(request, r.headers);
        return r;
      }

      const tenant = await getTenantBySlug(env, tenantSlug);
      if (!tenant) {
        const r = json({ error: 'tenant not found' }, 404);
        cors(request, r.headers);
        return r;
      }

      const m365Mapping = await getM365TenantMapping(env, tenant.id);
      const configured = Boolean(m365Mapping);
      
      const r = json({ 
        configured,
        mapping: m365Mapping || null,
        oauthAvailable: Boolean(env.M365_CLIENT_ID && env.M365_CLIENT_SECRET && env.M365_REDIRECT_URI)
      });
      cors(request, r.headers);
      return r;
    }

    const res = text('Not Found', 404);
    cors(request, res.headers);
    return res;
  }
};
