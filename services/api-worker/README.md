C360 API Worker

Scripts:
- npm run dev (local dev)
- npm run deploy (deploy)

Endpoints:
- GET /health
- GET /tenants (list)
- POST /tenants { name }
- GET /tenants/:id
- DELETE /tenants/:id
- GET /tenants/:tenantId/users
- POST /tenants/:tenantId/users { email, role? }

Notes:
- Use Wrangler D1 migrations to apply SQL in migrations/ to your bound database.
- Update `wrangler.toml` with real D1 `database_id` and KV `id` before deploy.

Environment variables:
- CORS_ORIGINS: Comma-separated allowlist of origins. If set, the Worker reflects the request Origin when it matches; otherwise returns `access-control-allow-origin: null`.
	- Example: `CORS_ORIGINS="https://app.example.com,https://admin.example.com"`
- CORS_ORIGIN: Single allowed origin (fallback when CORS_ORIGINS is not set). Example: `CORS_ORIGIN="https://app.example.com"`
- API_TOKEN: Optional Bearer token required for all routes except `/health`, `/openapi.json`, and `/docs`.
	- Send `Authorization: Bearer <token>` header on requests when enabled.

Wrangler configuration tips:
- Local dev: copy `.dev.vars.example` to `.dev.vars` and edit values for local development. Wrangler will load `.dev.vars` on `wrangler dev`.
- Set non-secret vars in `wrangler.toml` under `[vars]` or `[env.<name>.vars]`.
- Set secrets securely per environment:
	- `wrangler secret put API_TOKEN`
	- `wrangler secret put API_TOKEN --env staging`
	- `wrangler secret put API_TOKEN --env production`

Migrations (local examples):
- Create DB (once): `npm run d1:create`
- Apply migrations (managed): `npm run d1:apply`
- Apply SQL files directly (manual): `npm run d1:execute`
- List migration status: `npm run d1:list`
