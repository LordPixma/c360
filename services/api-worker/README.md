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

Migrations (local examples):
- Create DB (once): `npm run d1:create`
- Apply migrations (managed): `npm run d1:apply`
- Apply SQL files directly (manual): `npm run d1:execute`
- List migration status: `npm run d1:list`
