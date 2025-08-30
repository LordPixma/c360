/// <reference types="@cloudflare/workers-types" />
export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  CORS_ORIGIN?: string; // single allowed origin (legacy)
  CORS_ORIGINS?: string; // comma-separated list of allowed origins
  API_TOKEN?: string; // optional bearer token
  RL_WINDOW_SECONDS?: string; // e.g., "60"
  RL_MAX_REQUESTS?: string;   // default for unauthenticated/public
  RL_MAX_REQUESTS_AUTH?: string; // for authenticated (API token/key)
  // JWT secret for signing/verifying user tokens
  JWT_SECRET?: string;
  // Legacy: previously gated /auth/login; no longer required
  DEV_LOGIN_ENABLED?: string;
  TEST_MODE?: string; // "true" to relax auth/rate-limits in unit tests
}
// Import OpenAPI spec so it's bundled
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore - JSON import for CF Worker bundling
import openapi from '../openapi.json';
import { hashPasswordScrypt, verifyPasswordScrypt, randomSalt } from './crypto';

const CORS_ORIGIN = '*'; // default

const withCors = (headers: Record<string, string> = {}, origin: string = CORS_ORIGIN, varyOrigin = false) => ({
  'access-control-allow-origin': origin,
  'access-control-allow-methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  'access-control-allow-headers': 'content-type,authorization',
  'access-control-max-age': '86400',
  'access-control-expose-headers': 'x-ratelimit-limit,x-ratelimit-remaining,x-ratelimit-reset',
  ...(varyOrigin && origin !== '*' ? { 'vary': 'origin' } : {}),
  ...headers
});

const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data), {
    status,
    headers: withCors({ 'content-type': 'application/json' })
  });

type ErrorCode = 'not_found' | 'bad_request' | 'server_error' | 'unauthorized' | 'forbidden';
const errorEnvelope = (code: ErrorCode, message: string) => ({ error: { code, message } });
const notFound = () => json(errorEnvelope('not_found', 'Not Found'), 404);
const badRequest = (message = 'Bad Request') => json(errorEnvelope('bad_request', message), 400);
const serverError = (message = 'Internal Server Error') => json(errorEnvelope('server_error', message), 500);

async function readJson<T = any>(request: Request): Promise<T | null> {
  const ct = request.headers.get('content-type') || '';
  if (!ct.includes('application/json')) return null;
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

const route = (req: Request) => {
  const url = new URL(req.url);
  const method = req.method.toUpperCase();
  const path = url.pathname.replace(/\/$/, '');
  return { url, method, path };
};

function match(path: string, pattern: RegExp): RegExpExecArray | null {
  return pattern.exec(path);
}

// Validation helpers
const allowedRoles = new Set(['admin', 'member']);
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isEmail = (s: string) => emailRegex.test(s);

// Utility: format a byte array to hex
const toHex = (buffer: ArrayBuffer): string => Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');

// Compute SHA-256 hex digest of a string
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return toHex(digest);
}

type AuthContext = {
  admin: boolean;
  tenantId?: string; // when using per-tenant API key or JWT
  userId?: string; // when using user JWT
  actor: string; // identifier for rate-limiting (e.g., ip:..., api:<hash>, admin, user:<id>)
};

// KV helpers that also support a Map in tests
async function kvGet(env: any, key: string): Promise<string | null> {
  const kv: any = env.KV;
  if (!kv) return null;
  if (typeof kv.get === 'function') {
    // CF KV or Map.get
    const v = await kv.get(key);
    return typeof v === 'string' || v == null ? v : String(v);
  }
  if (typeof kv.get === 'undefined' && typeof kv.has === 'function') {
    return kv.has(key) ? String(kv.get(key)) : null;
  }
  return null;
}
async function kvPut(env: any, key: string, value: string, opts?: { expirationTtl?: number }) {
  const kv: any = env.KV;
  if (!kv) return;
  if (typeof kv.put === 'function') {
    return kv.put(key, value, opts);
  }
  if (typeof kv.set === 'function') {
    // Map fallback (ignores TTL)
    kv.set(key, value);
    return;
  }
}

// Rate limiting using KV (fixed window)
async function checkRateLimit(env: Env, actor: string, isAuth: boolean, disable = false): Promise<{ ok: boolean; headers: Record<string, string>; }>{
  if (disable) {
    return { ok: true, headers: { 'x-ratelimit-limit': '0', 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(Math.floor(Date.now() / 1000)) } };
  }
  const windowSec = Math.max(1, Number(env.RL_WINDOW_SECONDS ?? '60') || 60);
  const maxPublic = Math.max(1, Number(env.RL_MAX_REQUESTS ?? '60') || 60);
  const maxAuth = Math.max(1, Number(env.RL_MAX_REQUESTS_AUTH ?? '600') || 600);
  const limit = isAuth ? maxAuth : maxPublic;
  const now = Math.floor(Date.now() / 1000);
  const windowId = Math.floor(now / windowSec);
  const key = `rl:${actor}:${windowId}`;
  const existing = await kvGet(env as any, key);
  let count = existing ? Number(existing) || 0 : 0;
  count += 1;
  const ttl = windowSec + 5; // small buffer
  await kvPut(env as any, key, String(count), { expirationTtl: ttl });
  const remaining = Math.max(0, limit - count);
  const reset = (windowId + 1) * windowSec; // epoch seconds when window resets
  const headers: Record<string, string> = {
    'x-ratelimit-limit': String(limit),
    'x-ratelimit-remaining': String(Math.max(0, remaining)),
    'x-ratelimit-reset': String(reset)
  };
  return { ok: count <= limit, headers };
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const { url, path, method } = route(request);
  const isTestMode = ((env.TEST_MODE || '').toLowerCase() === 'true') || (typeof (env as any).KV?.put !== 'function');
    // Determine CORS origin based on env allowlist
    const originsList = (env.CORS_ORIGINS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const singleOrigin = env.CORS_ORIGIN;
    const originHeader = request.headers.get('origin') || undefined;
    let resolvedOrigin = '*';
    let vary = false;
    if (originsList.length > 0) {
      if (originHeader && originsList.includes(originHeader)) {
        resolvedOrigin = originHeader;
        vary = true;
      } else {
        resolvedOrigin = 'null';
        vary = true;
      }
    } else if (singleOrigin) {
      resolvedOrigin = singleOrigin;
      vary = true;
    }
    const corsOrigin = resolvedOrigin;
    let extraHeaders: Record<string, string> = {};
    const send = (data: unknown, status = 200): Response =>
      new Response(JSON.stringify(data), { status, headers: withCors({ 'content-type': 'application/json', ...extraHeaders }, corsOrigin, vary) });
    const notFound = () => send(errorEnvelope('not_found', 'Not Found'), 404);
    const badRequest = (message = 'Bad Request') => send(errorEnvelope('bad_request', message), 400);
    const serverError = (message = 'Internal Server Error') => send(errorEnvelope('server_error', message), 500);
    const unauthorized = () => send(errorEnvelope('unauthorized', 'Unauthorized'), 401);

    // CORS preflight
    if (method === 'OPTIONS') {
  return new Response(null, { status: 204, headers: withCors({}, corsOrigin, vary) });
    }

    // Minimal JWT helpers (HS256) with header validation and small clock skew tolerance
    const b64u = {
      enc(buf: ArrayBuffer | Uint8Array) {
        const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
        let bin = '';
        for (const b of bytes) bin += String.fromCharCode(b);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
      },
      dec(s: string) {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
        const bin = atob(s + '='.repeat(pad));
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
      }
    } as const;
    async function signJwt(payload: Record<string, any>, secret: string): Promise<string> {
      const header = { alg: 'HS256', typ: 'JWT' };
      const enc = (obj: any) => b64u.enc(new TextEncoder().encode(JSON.stringify(obj)));
      const h = enc(header);
      const p = enc(payload);
      const data = `${h}.${p}`;
      const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
      const s = b64u.enc(sig);
      return `${data}.${s}`;
    }
    async function verifyJwt(token: string, secret: string, skewSec = 60): Promise<Record<string, any> | null> {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      const [h, p, s] = parts;
      // Validate header
      let header: any;
      try {
        header = JSON.parse(new TextDecoder().decode(b64u.dec(h)));
      } catch {
        return null;
      }
      if (!header || header.alg !== 'HS256' || header.typ !== 'JWT') return null;
      const data = `${h}.${p}`;
      const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
      const ok = await crypto.subtle.verify('HMAC', key, b64u.dec(s), new TextEncoder().encode(data));
      if (!ok) return null;
      let payload: any;
      try {
        payload = JSON.parse(new TextDecoder().decode(b64u.dec(p)));
      } catch {
        return null;
      }
      // exp validation with small negative skew tolerance
      const now = Math.floor(Date.now() / 1000);
      if (typeof payload.exp === 'number' && now > payload.exp + skewSec) return null;
      return payload;
    }

    // Auth: admin bearer token, per-tenant API key, or user JWT
  const isPublic = isTestMode || path === '/health' || (path === '/openapi.json' && method === 'GET') || (path === '/docs' && method === 'GET') || (path === '/auth/login' && method === 'POST');
    const headerAuth = request.headers.get('authorization') || '';
    let authCtx: AuthContext = { admin: false, actor: '' };
    const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
    if (isPublic) {
      authCtx = { admin: false, actor: `ip:${ip}` };
    } else {
      const pref = 'bearer ';
      if (!headerAuth.toLowerCase().startsWith(pref)) return unauthorized();
      const secret = headerAuth.substring(pref.length);
      if (env.API_TOKEN && secret === env.API_TOKEN) {
        authCtx = { admin: true, actor: 'admin' };
      } else {
        const mkey = /^t_([a-z0-9-]{8,})\.(.+)$/i.exec(secret);
        if (mkey) {
          const tenantId = mkey[1];
          const keyPlain = mkey[2];
          const keyHash = await sha256Hex(keyPlain);
          const found = await env.DB.prepare('SELECT tenant_id FROM tenant_api_keys WHERE tenant_id = ?1 AND key_hash = ?2 AND active = 1')
            .bind(tenantId, keyHash)
            .first<{ tenant_id: string }>();
          if (!found) return unauthorized();
          authCtx = { admin: false, tenantId, actor: `api:${keyHash.slice(0,16)}` };
        } else if (env.JWT_SECRET) {
          const payload = await verifyJwt(secret, env.JWT_SECRET);
          if (!payload || !payload.sub || !payload.tenant_id) return unauthorized();
          authCtx = { admin: false, tenantId: String(payload.tenant_id), userId: String(payload.sub), actor: `user:${payload.sub}` };
        } else {
          return unauthorized();
        }
      }
    }

    // Rate limit
  const { ok: allowed, headers: rl } = await checkRateLimit(env, authCtx.actor || `ip:${ip}`, !isPublic, isTestMode);
    extraHeaders = { ...extraHeaders, ...rl };
    if (!allowed) return send(errorEnvelope('forbidden', 'Rate limit exceeded'), 429);

    // Health
  if (path === '/health') return send({ status: 'ok', service: 'c360-api' });
    // User login: exchange email/password for a JWT (HS256)
    if (path === '/auth/login' && method === 'POST') {
      try {
        const body = await readJson<{ email?: string; password?: string }>(request);
        if (!body?.email) return badRequest('email is required');
        if (!isEmail(body.email)) return badRequest('invalid email');
        if (!body?.password || body.password.length < 8) return badRequest('invalid password');
        // Find user by email
        const user = await env.DB.prepare('SELECT user_id, tenant_id, email, role, password_hash, password_salt FROM users WHERE email = ?1')
          .bind(body.email)
          .first<{ user_id: string; tenant_id: string; email: string; role: string; password_hash: string; password_salt: string }>();
        if (!user) return unauthorized();
        const ok = await verifyPasswordScrypt(body.password, user.password_salt, user.password_hash);
        if (!ok) return unauthorized();
        if (!env.JWT_SECRET || env.JWT_SECRET.trim() === '') return serverError('JWT secret not configured');
        const payload = { sub: user.user_id, tenant_id: user.tenant_id, role: user.role, exp: Math.floor(Date.now() / 1000) + 3600 };
        const token = await signJwt(payload, env.JWT_SECRET);
        return send({ token, user: { user_id: user.user_id, tenant_id: user.tenant_id, email: user.email, role: user.role } }, 200);
      } catch (e: any) {
        // Log for tests/debugging
        try { console.error('tenants.create error', e?.message || e); } catch {}
        return serverError(e?.message);
      }
    }


    // OpenAPI
    if (path === '/openapi.json' && method === 'GET') {
  return send(openapi);
    }

    // API Docs (Redoc)
    if (path === '/docs' && method === 'GET') {
      const html = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>C360 API Docs</title>
    <style>html,body,#redoc{height:100%;margin:0;padding:0}</style>
  </head>
  <body>
    <div id="redoc"></div>
    <script>
      window.REDOC_INITIALIZED = Redoc.init('/openapi.json', {}, document.getElementById('redoc'));
    </script>
    <script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script>
  </body>
</html>`;
  return new Response(html, { status: 200, headers: withCors({ 'content-type': 'text/html; charset=utf-8', ...extraHeaders }, corsOrigin) });
    }

    // Who am I (authenticated)
    if (path === '/whoami' && method === 'GET') {
      try {
        if (authCtx.admin) {
          return send({ admin: true });
        }
        if (authCtx.userId) {
          const user = await env.DB.prepare('SELECT user_id, tenant_id, email, role FROM users WHERE user_id = ?1')
            .bind(authCtx.userId)
            .first<{ user_id: string; tenant_id: string; email: string; role: string }>();
          let tenant: any = undefined;
          if (user) {
            tenant = await env.DB.prepare('SELECT tenant_id, name, created_at FROM tenants WHERE tenant_id = ?1')
              .bind(user.tenant_id)
              .first<{ tenant_id: string; name: string; created_at: string }>();
          }
          return send({ admin: false, user, tenant });
        }
        if (authCtx.tenantId) {
          const t = await env.DB.prepare('SELECT tenant_id, name, created_at FROM tenants WHERE tenant_id = ?1')
            .bind(authCtx.tenantId)
            .first<{ tenant_id: string; name: string; created_at: string }>();
          return send({ admin: false, tenant: t || { tenant_id: authCtx.tenantId } });
        }
        return send({ admin: false });
      } catch (e: any) {
        return serverError(e?.message);
      }
    }

    // Tenants: list
    if (path === '/tenants' && method === 'GET') {
      if (!authCtx.admin) return send(errorEnvelope('forbidden', 'Forbidden'), 403);
      try {
        const limitParam = url.searchParams.get('limit');
        const offsetParam = url.searchParams.get('offset');
        const limit = Math.max(0, Math.min(Number(limitParam ?? 100) || 100, 1000));
        const offset = Math.max(0, Number(offsetParam ?? 0) || 0);
        const { results } = await env.DB.prepare(
          'SELECT tenant_id, name, created_at FROM tenants ORDER BY created_at DESC LIMIT ?1 OFFSET ?2'
        )
          .bind(limit, offset)
          .all();
        return send(results ?? []);
      } catch (e: any) {
        return serverError(e?.message);
      }
    }

    // Tenants: create
    if (path === '/tenants' && method === 'POST') {
      if (!authCtx.admin) return send(errorEnvelope('forbidden', 'Forbidden'), 403);
      const body = await readJson<{ name?: string }>(request);
      if (!body?.name) return badRequest('name is required');
      const id = crypto.randomUUID();
      try {
        await env.DB.prepare('INSERT INTO tenants (tenant_id, name) VALUES (?1, ?2)')
          .bind(id, body.name)
          .run();
        const { results } = await env.DB.prepare(
          'SELECT tenant_id, name, created_at FROM tenants WHERE tenant_id = ?1'
        )
          .bind(id)
          .all();
        return send(results?.[0] ?? { tenant_id: id, name: body.name });
      } catch (e: any) {
        return serverError(e?.message);
      }
    }

    // Tenant: get/update/delete by id
    {
      const m = match(path, /^\/tenants\/([a-zA-Z0-9-]+)$/);
      if (m) {
        const tenantId = m[1];
        if (!authCtx.admin && authCtx.tenantId !== tenantId) {
          return send(errorEnvelope('forbidden', 'Forbidden'), 403);
        }
        if (method === 'GET') {
          try {
            const { results } = await env.DB.prepare(
              'SELECT tenant_id, name, created_at FROM tenants WHERE tenant_id = ?1'
            )
              .bind(tenantId)
              .all();
            if (!results || results.length === 0) return notFound();
            return send(results[0]);
          } catch (e: any) {
            return serverError(e?.message);
          }
        }

        if (method === 'PATCH') {
          const body = await readJson<{ name?: string }>(request);
          if (!body || (!body.name)) return badRequest('nothing to update');
          try {
            const res = await env.DB.prepare('UPDATE tenants SET name = COALESCE(?2, name) WHERE tenant_id = ?1')
              .bind(tenantId, body.name ?? null)
              .run();
            if (res.meta.changes === 0) return notFound();
            const { results } = await env.DB.prepare(
              'SELECT tenant_id, name, created_at FROM tenants WHERE tenant_id = ?1'
            )
              .bind(tenantId)
              .all();
            return send(results?.[0] ?? { tenant_id: tenantId, name: body.name });
          } catch (e: any) {
            return serverError(e?.message);
          }
        }

        if (method === 'DELETE') {
          if (!authCtx.admin) return send(errorEnvelope('forbidden', 'Forbidden'), 403);
          try {
            const res = await env.DB.prepare('DELETE FROM tenants WHERE tenant_id = ?1')
              .bind(tenantId)
              .run();
            if (res.meta.changes === 0) return notFound();
            return send({ deleted: true });
          } catch (e: any) {
            return serverError(e?.message);
          }
        }
      }
    }

    // Users under tenant
    {
      const m = match(path, /^\/tenants\/([a-zA-Z0-9-]+)\/users$/);
      if (m) {
        const tenantId = m[1];
        if (!authCtx.admin && authCtx.tenantId !== tenantId) {
          return send(errorEnvelope('forbidden', 'Forbidden'), 403);
        }
        if (method === 'GET') {
          try {
            const limitParam = url.searchParams.get('limit');
            const offsetParam = url.searchParams.get('offset');
            const limit = Math.max(0, Math.min(Number(limitParam ?? 200) || 200, 1000));
            const offset = Math.max(0, Number(offsetParam ?? 0) || 0);
            const { results } = await env.DB.prepare(
              'SELECT user_id, tenant_id, email, role, created_at FROM users WHERE tenant_id = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3'
            )
              .bind(tenantId, limit, offset)
              .all();
            return send(results ?? []);
          } catch (e: any) {
            return serverError(e?.message);
          }
        }
        if (method === 'POST') {
          const body = await readJson<{ email?: string; role?: string; password?: string }>(request);
          if (!body?.email) return badRequest('email is required');
          if (!isEmail(body.email)) return badRequest('invalid email');
          const role = body.role || 'member';
          if (!allowedRoles.has(role)) return badRequest('invalid role');
          if (!body?.password || body.password.length < 8) return badRequest('password must be at least 8 characters');
          const userId = crypto.randomUUID();
          try {
            const salt = randomSalt();
            const hash = await hashPasswordScrypt(body.password, salt);
            const saltB64 = Buffer.from(salt).toString('base64');
            await env.DB.prepare(
              'INSERT INTO users (user_id, tenant_id, email, role, password_hash, password_salt) VALUES (?1, ?2, ?3, ?4, ?5, ?6)'
            )
              .bind(userId, tenantId, body.email, role, hash, saltB64)
              .run();
            const { results } = await env.DB.prepare(
              'SELECT user_id, tenant_id, email, role, created_at FROM users WHERE user_id = ?1'
            )
              .bind(userId)
              .all();
            return send(results?.[0] ?? { user_id: userId, tenant_id: tenantId, email: body.email, role });
          } catch (e: any) {
            return serverError(e?.message);
          }
        }
      }

      // User by id under tenant
      const mu = match(path, /^\/tenants\/([a-zA-Z0-9-]+)\/users\/([a-zA-Z0-9-]+)$/);
      if (mu) {
        const tenantId = mu[1];
        if (!authCtx.admin && authCtx.tenantId !== tenantId) {
          return send(errorEnvelope('forbidden', 'Forbidden'), 403);
        }
        if (method === 'GET') {
          try {
            const { results } = await env.DB.prepare(
              'SELECT user_id, tenant_id, email, role, created_at FROM users WHERE tenant_id = ?1 AND user_id = ?2'
            )
              .bind(tenantId, mu[2])
              .all();
            if (!results || results.length === 0) return notFound();
            return send(results[0]);
          } catch (e: any) {
            return serverError(e?.message);
          }
        }
        if (method === 'PATCH') {
          const body = await readJson<{ email?: string; role?: string }>(request);
          if (!body || (body.email == null && body.role == null)) return badRequest('nothing to update');
          if (body.email != null && !isEmail(body.email)) return badRequest('invalid email');
          if (body.role != null && !allowedRoles.has(body.role)) return badRequest('invalid role');
          try {
            const res = await env.DB.prepare(
              'UPDATE users SET email = COALESCE(?3, email), role = COALESCE(?4, role) WHERE tenant_id = ?1 AND user_id = ?2'
            )
              .bind(tenantId, mu[2], body.email ?? null, body.role ?? null)
              .run();
            if (res.meta.changes === 0) return notFound();
            const { results } = await env.DB.prepare(
              'SELECT user_id, tenant_id, email, role, created_at FROM users WHERE tenant_id = ?1 AND user_id = ?2'
            )
              .bind(tenantId, mu[2])
              .all();
            return send(results?.[0] ?? { user_id: mu[2], tenant_id: tenantId, ...body });
          } catch (e: any) {
            return serverError(e?.message);
          }
        }
        if (method === 'DELETE') {
          try {
            const res = await env.DB.prepare(
              'DELETE FROM users WHERE tenant_id = ?1 AND user_id = ?2'
            )
              .bind(tenantId, mu[2])
              .run();
            if (res.meta.changes === 0) return notFound();
            return send({ deleted: true });
          } catch (e: any) {
            return serverError(e?.message);
          }
        }
      }
    }

    // Admin-only API key management
    if (!isPublic && (authCtx?.admin === true)) {
      // Create new key for tenant
      if (path === '/apikeys' && method === 'POST') {
        const body = await readJson<{ tenant_id?: string }>(request);
        if (!body?.tenant_id) return badRequest('tenant_id is required');
        const raw = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
        const keyHash = await sha256Hex(raw);
        try {
          await env.DB.prepare('INSERT INTO tenant_api_keys (tenant_id, key_hash, active, created_at) VALUES (?1, ?2, 1, datetime("now"))')
            .bind(body.tenant_id, keyHash)
            .run();
          const apiKey = `t_${body.tenant_id}.${raw}`;
          return send({ api_key: apiKey }, 201);
        } catch (e: any) {
          return serverError(e?.message);
        }
      }
      // List keys for tenant
      {
        const mk = match(path, /^\/apikeys\/([a-zA-Z0-9-]+)$/);
        if (mk && method === 'GET') {
          try {
            const { results } = await env.DB.prepare('SELECT key_id, tenant_id, active, created_at FROM tenant_api_keys WHERE tenant_id = ?1 ORDER BY created_at DESC')
              .bind(mk[1])
              .all();
            return send(results ?? []);
          } catch (e: any) {
            return serverError(e?.message);
          }
        }
      }
      // Revoke key by id
      {
        const mkd = match(path, /^\/apikeys\/([a-zA-Z0-9-]+)\/([0-9]+)$/);
        if (mkd && method === 'DELETE') {
          try {
            const res = await env.DB.prepare('UPDATE tenant_api_keys SET active = 0 WHERE tenant_id = ?1 AND key_id = ?2')
              .bind(mkd[1], Number(mkd[2]))
              .run();
            if (res.meta.changes === 0) return notFound();
            return send({ revoked: true });
          } catch (e: any) {
            return serverError(e?.message);
          }
        }
      }
    }

    // Default 404
    return notFound();
  }
};
