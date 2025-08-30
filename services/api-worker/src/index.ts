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
  DEV_LOGIN_ENABLED?: string; // "true" to enable /auth/login for local/dev only
}
// Import OpenAPI spec so it's bundled
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore - JSON import for CF Worker bundling
import openapi from '../openapi.json';

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
  tenantId?: string; // when using per-tenant API key
  actor: string; // identifier for rate-limiting (e.g., ip:..., api:<hash>, admin)
};

// Rate limiting using KV (fixed window)
async function checkRateLimit(env: Env, actor: string, isAuth: boolean): Promise<{ ok: boolean; headers: Record<string, string>; }>{
  const windowSec = Math.max(1, Number(env.RL_WINDOW_SECONDS ?? '60') || 60);
  const maxPublic = Math.max(1, Number(env.RL_MAX_REQUESTS ?? '60') || 60);
  const maxAuth = Math.max(1, Number(env.RL_MAX_REQUESTS_AUTH ?? '600') || 600);
  const limit = isAuth ? maxAuth : maxPublic;
  const now = Math.floor(Date.now() / 1000);
  const windowId = Math.floor(now / windowSec);
  const key = `rl:${actor}:${windowId}`;
  const existing = await env.KV.get(key);
  let count = existing ? Number(existing) || 0 : 0;
  count += 1;
  const ttl = windowSec + 5; // small buffer
  await env.KV.put(key, String(count), { expirationTtl: ttl });
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

    // Auth: admin bearer token or per-tenant API key
    const isPublic =
      path === '/health' ||
      (path === '/openapi.json' && method === 'GET') ||
      (path === '/docs' && method === 'GET') ||
      (path === '/auth/login' && method === 'POST') ||
      (path === '/auth/logout' && method === 'POST');

    const headerAuth = request.headers.get('authorization') || '';
    const cookieHeader = request.headers.get('cookie') || '';
    const getCookie = (name: string): string | undefined => {
      // Safe cookie parsing: split and compare, no regex
      for (const part of cookieHeader.split(';')) {
        const [k, ...v] = part.trim().split('=');
        if (k === name) return decodeURIComponent(v.join('='));
      }
      return undefined;
    };
    const cookieToken = getCookie('auth_token');

    let authCtx: AuthContext = { admin: false, actor: '' };
    const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
    if (isPublic) {
      authCtx = { admin: false, actor: `ip:${ip}` };
    } else {
      const pref = 'bearer ';
      let secret: string | undefined;
      if (headerAuth.toLowerCase().startsWith(pref)) secret = headerAuth.substring(pref.length);
      else if (cookieToken) secret = cookieToken;
      if (!secret) return unauthorized();
      if (env.API_TOKEN && secret === env.API_TOKEN) {
        authCtx = { admin: true, actor: 'admin' };
      } else {
        const mkey = /^t_([a-z0-9-]{8,})\.(.+)$/i.exec(secret);
        if (!mkey) return unauthorized();
        const tenantId = mkey[1];
        const keyPlain = mkey[2];
        const keyHash = await sha256Hex(keyPlain);
        const found = await env.DB.prepare(
          'SELECT tenant_id FROM tenant_api_keys WHERE tenant_id = ?1 AND key_hash = ?2 AND active = 1'
        )
          .bind(tenantId, keyHash)
          .first<{ tenant_id: string }>();
        if (!found) return unauthorized();
        authCtx = { admin: false, tenantId, actor: `api:${keyHash.slice(0, 16)}` };
      }
    }

    // Rate limit
    const { ok: allowed, headers: rl } = await checkRateLimit(env, authCtx.actor || `ip:${ip}`, !isPublic);
    extraHeaders = { ...extraHeaders, ...rl };
    if (!allowed) return send(errorEnvelope('forbidden', 'Rate limit exceeded'), 429);

    // Health
  if (path === '/health') return send({ status: 'ok', service: 'c360-api' });
    // Development-only auth: exchange email/password for a tenant API key
    if (path === '/auth/login' && method === 'POST') {
      try {
        if ((env.DEV_LOGIN_ENABLED || '').toLowerCase() !== 'true') {
          return notFound();
        }
        const body = await readJson<{ email?: string; password?: string; tenant_id?: string; }>(request);
        if (!body?.email) return badRequest('email is required');
        if (!isEmail(body.email)) return badRequest('invalid email');
        if (!body?.password || body.password.length < 8) return badRequest('invalid password');

        // Resolve tenant
        let tenantId = body.tenant_id;
        let tenantName: string | undefined;
        if (tenantId) {
          const found = await env.DB.prepare('SELECT tenant_id, name, created_at FROM tenants WHERE tenant_id = ?1')
            .bind(tenantId)
            .first<{ tenant_id: string; name: string; created_at: string }>();
          if (!found) return badRequest('tenant not found');
          tenantName = found.name;
        } else {
          // Create a dev tenant if none provided
          tenantId = crypto.randomUUID();
          tenantName = `Dev Tenant (${body.email})`;
          await env.DB.prepare('INSERT INTO tenants (tenant_id, name) VALUES (?1, ?2)')
            .bind(tenantId, tenantName)
            .run();
        }

        // Upsert user within tenant
        let user = await env.DB.prepare('SELECT user_id, tenant_id, email, role, created_at FROM users WHERE tenant_id = ?1 AND email = ?2')
          .bind(tenantId, body.email)
          .first<{ user_id: string; tenant_id: string; email: string; role: string; created_at: string }>();
        if (!user) {
          const uid = crypto.randomUUID();
          await env.DB.prepare('INSERT INTO users (user_id, tenant_id, email, role) VALUES (?1, ?2, ?3, ?4)')
            .bind(uid, tenantId, body.email, 'member')
            .run();
          user = await env.DB.prepare('SELECT user_id, tenant_id, email, role, created_at FROM users WHERE user_id = ?1')
            .bind(uid)
            .first<{ user_id: string; tenant_id: string; email: string; role: string; created_at: string }>();
        }

        // Issue a tenant API key
        const raw = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
        const keyHash = await sha256Hex(raw);
        await env.DB.prepare('INSERT INTO tenant_api_keys (tenant_id, key_hash, active, created_at) VALUES (?1, ?2, 1, datetime("now"))')
          .bind(tenantId, keyHash)
          .run();
        const apiKey = `t_${tenantId}.${raw}`;
        extraHeaders['set-cookie'] = `auth_token=${apiKey}; HttpOnly; Secure; SameSite=Strict; Path=/`;
        return send(
          {
            api_key: apiKey,
            tenant_id: tenantId,
            tenant: tenantName ? { tenant_id: tenantId, name: tenantName } : { tenant_id: tenantId },
            user
          },
          200
        );
      } catch (e: any) {
        return serverError(e?.message);
      }
    }
    if (path === '/auth/logout' && method === 'POST') {
      extraHeaders['set-cookie'] = 'auth_token=; Max-Age=0; HttpOnly; Secure; SameSite=Strict; Path=/';
      return send({ ok: true });
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

    // Tenant: get by id
    {
      const m = match(path, /^\/tenants\/([a-zA-Z0-9-]+)$/);
      if (m && method === 'GET') {
        try {
          const { results } = await env.DB.prepare(
            'SELECT tenant_id, name, created_at FROM tenants WHERE tenant_id = ?1'
          )
            .bind(m[1])
            .all();
          if (!results || results.length === 0) return notFound();
          return send(results[0]);
        } catch (e: any) {
          return serverError(e?.message);
        }
      }

      // Tenant: update (PATCH)
      if (m && method === 'PATCH') {
        const body = await readJson<{ name?: string }>(request);
        if (!body || (!body.name)) return badRequest('nothing to update');
        try {
          const res = await env.DB.prepare('UPDATE tenants SET name = COALESCE(?2, name) WHERE tenant_id = ?1')
            .bind(m[1], body.name ?? null)
            .run();
          if (res.meta.changes === 0) return notFound();
          const { results } = await env.DB.prepare(
            'SELECT tenant_id, name, created_at FROM tenants WHERE tenant_id = ?1'
          )
            .bind(m[1])
            .all();
          return send(results?.[0] ?? { tenant_id: m[1], name: body.name });
        } catch (e: any) {
          return serverError(e?.message);
        }
      }

      // Tenant: delete
      if (m && method === 'DELETE') {
        try {
          const res = await env.DB.prepare('DELETE FROM tenants WHERE tenant_id = ?1')
            .bind(m[1])
            .run();
          if (res.meta.changes === 0) return notFound();
          return send({ deleted: true });
        } catch (e: any) {
          return serverError(e?.message);
        }
      }
    }

    // Users under tenant
    {
      const m = match(path, /^\/tenants\/([a-zA-Z0-9-]+)\/users$/);
      if (m && method === 'GET') {
        try {
          const limitParam = url.searchParams.get('limit');
          const offsetParam = url.searchParams.get('offset');
          const limit = Math.max(0, Math.min(Number(limitParam ?? 200) || 200, 1000));
          const offset = Math.max(0, Number(offsetParam ?? 0) || 0);
          const { results } = await env.DB.prepare(
            'SELECT user_id, tenant_id, email, role, created_at FROM users WHERE tenant_id = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3'
          )
            .bind(m[1], limit, offset)
            .all();
          return send(results ?? []);
        } catch (e: any) {
          return serverError(e?.message);
        }
      }
      if (m && method === 'POST') {
        const body = await readJson<{ email?: string; role?: string }>(request);
        if (!body?.email) return badRequest('email is required');
  if (!isEmail(body.email)) return badRequest('invalid email');
  const role = body.role || 'member';
  if (!allowedRoles.has(role)) return badRequest('invalid role');
        const userId = crypto.randomUUID();
        try {
          await env.DB.prepare(
            'INSERT INTO users (user_id, tenant_id, email, role) VALUES (?1, ?2, ?3, ?4)'
          )
            .bind(userId, m[1], body.email, role)
            .run();
          const { results } = await env.DB.prepare(
            'SELECT user_id, tenant_id, email, role, created_at FROM users WHERE user_id = ?1'
          )
            .bind(userId)
            .all();
          return send(results?.[0] ?? { user_id: userId, tenant_id: m[1], email: body.email, role });
        } catch (e: any) {
          return serverError(e?.message);
        }
      }

      // User by id under tenant
      const mu = match(path, /^\/tenants\/([a-zA-Z0-9-]+)\/users\/([a-zA-Z0-9-]+)$/);
      if (mu && method === 'GET') {
        try {
          const { results } = await env.DB.prepare(
            'SELECT user_id, tenant_id, email, role, created_at FROM users WHERE tenant_id = ?1 AND user_id = ?2'
          )
            .bind(mu[1], mu[2])
            .all();
          if (!results || results.length === 0) return notFound();
          return send(results[0]);
        } catch (e: any) {
          return serverError(e?.message);
        }
      }
      if (mu && method === 'PATCH') {
        const body = await readJson<{ email?: string; role?: string }>(request);
        if (!body || (body.email == null && body.role == null)) return badRequest('nothing to update');
  if (body.email != null && !isEmail(body.email)) return badRequest('invalid email');
  if (body.role != null && !allowedRoles.has(body.role)) return badRequest('invalid role');
        try {
          const res = await env.DB.prepare(
            'UPDATE users SET email = COALESCE(?3, email), role = COALESCE(?4, role) WHERE tenant_id = ?1 AND user_id = ?2'
          )
            .bind(mu[1], mu[2], body.email ?? null, body.role ?? null)
            .run();
          if (res.meta.changes === 0) return notFound();
          const { results } = await env.DB.prepare(
            'SELECT user_id, tenant_id, email, role, created_at FROM users WHERE tenant_id = ?1 AND user_id = ?2'
          )
            .bind(mu[1], mu[2])
            .all();
          return send(results?.[0] ?? { user_id: mu[2], tenant_id: mu[1], ...body });
        } catch (e: any) {
          return serverError(e?.message);
        }
      }
      if (mu && method === 'DELETE') {
        try {
          const res = await env.DB.prepare(
            'DELETE FROM users WHERE tenant_id = ?1 AND user_id = ?2'
          )
            .bind(mu[1], mu[2])
            .run();
          if (res.meta.changes === 0) return notFound();
          return send({ deleted: true });
        } catch (e: any) {
          return serverError(e?.message);
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
