/// <reference types="@cloudflare/workers-types" />
export interface Env {
  DB: D1Database;
  KV: KVNamespace;
}

const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json' }
  });

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return json({ status: "ok", service: "c360-api" });
    }

    if (url.pathname === "/tenants" && request.method === "GET") {
      const { results } = await env.DB.prepare("SELECT tenant_id, name FROM tenants LIMIT 50").all();
      return json(results ?? []);
    }

    if (url.pathname === "/migrate" && request.method === "POST") {
      // Very basic migration runner: runs all .sql files in migrations folder packaged with the worker
      // In real setups, use Wrangler d1 migrations
      return json({ message: "Migrations should be run via Wrangler D1 CLI." }, 202);
    }

    return json({ error: "Not Found" }, 404);
  }
};
