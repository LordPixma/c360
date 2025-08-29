/// <reference types="@cloudflare/workers-types" />
export interface Env {
  DB: D1Database;
  KV: KVNamespace;
}
// Import OpenAPI spec so it's bundled
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore - JSON import for CF Worker bundling
import openapi from '../openapi.json';

const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json' }
  });

const notFound = () => json({ error: 'Not Found' }, 404);
const badRequest = (message = 'Bad Request') => json({ error: message }, 400);
const serverError = (message = 'Internal Server Error') => json({ error: message }, 500);

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

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const { path, method } = route(request);

    // Health
    if (path === '/health') return json({ status: 'ok', service: 'c360-api' });

    // OpenAPI
    if (path === '/openapi.json' && method === 'GET') {
      return json(openapi);
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
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
    }

    // Tenants: list
    if (path === '/tenants' && method === 'GET') {
      try {
        const { results } = await env.DB.prepare(
          'SELECT tenant_id, name, created_at FROM tenants ORDER BY created_at DESC LIMIT 100'
        ).all();
        return json(results ?? []);
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
        return json(results?.[0] ?? { tenant_id: id, name: body.name });
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
          return json(results[0]);
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
          return json(results?.[0] ?? { tenant_id: m[1], name: body.name });
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
          return json({ deleted: true });
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
          const { results } = await env.DB.prepare(
            'SELECT user_id, tenant_id, email, role, created_at FROM users WHERE tenant_id = ?1 ORDER BY created_at DESC LIMIT 200'
          )
            .bind(m[1])
            .all();
          return json(results ?? []);
        } catch (e: any) {
          return serverError(e?.message);
        }
      }
      if (m && method === 'POST') {
        const body = await readJson<{ email?: string; role?: string }>(request);
        if (!body?.email) return badRequest('email is required');
        const role = body.role || 'member';
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
          return json(results?.[0] ?? { user_id: userId, tenant_id: m[1], email: body.email, role });
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
          return json(results[0]);
        } catch (e: any) {
          return serverError(e?.message);
        }
      }
      if (mu && method === 'PATCH') {
        const body = await readJson<{ email?: string; role?: string }>(request);
        if (!body || (body.email == null && body.role == null)) return badRequest('nothing to update');
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
          return json(results?.[0] ?? { user_id: mu[2], tenant_id: mu[1], ...body });
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
          return json({ deleted: true });
        } catch (e: any) {
          return serverError(e?.message);
        }
      }
    }

    // Default 404
    return notFound();
  }
};
