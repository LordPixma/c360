C360 API Worker

Scripts:
- npm run dev (local dev)
- npm run deploy (deploy)

Endpoints:
- GET /health
- POST /auth/login { email, password } -> { token }
- GET /tenants (list)
- POST /tenants { name }
- GET /tenants/:id
- DELETE /tenants/:id
- GET /tenants/:tenantId/users
- POST /tenants/:tenantId/users { email, role? }

Notes:
- Use Wrangler D1 migrations to apply SQL in migrations/ to your bound database.
- Update `wrangler.toml` with real D1 `database_id` and KV `id` before deploy.

Authentication:
- Admin token (for platform admin routes):
	- Set `API_TOKEN` secret and send `Authorization: Bearer <API_TOKEN>`.
	- Required for admin-only routes like `GET /tenants`, `POST /tenants`, and creating users.
- Per-tenant API key (backward compatible):
	- Format: `t_<tenantId>.<secret>` in `Authorization: Bearer ...`.
	- Keys are stored hashed; can be created/revoked via admin endpoints.
- User JWT (recommended):
	- Obtain by POST `/auth/login` with `{ email, password }`.
	- The response includes `{ token }` (HS256 JWT). Use it via `Authorization: Bearer <token>`.
	- `GET /whoami` returns `{ admin, user?, tenant? }` depending on the token.

Header expectations:
- Always send `Authorization: Bearer <token-or-key>` on protected routes.
- CORS: `access-control-allow-origin` reflects configured allowlist. `content-type` and `authorization` headers are allowed.

Environment variables:
- CORS_ORIGINS: Comma-separated allowlist of origins. If set, the Worker reflects the request Origin when it matches; otherwise returns `access-control-allow-origin: null`.
	- Example: `CORS_ORIGINS="https://app.example.com,https://admin.example.com"`
- CORS_ORIGIN: Single allowed origin (fallback when CORS_ORIGINS is not set). Example: `CORS_ORIGIN="https://app.example.com"`
- API_TOKEN: Optional Bearer token for admin access.
- JWT_SECRET: Required for issuing and verifying user JWTs. Set via `wrangler secret put JWT_SECRET`.

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

Password columns rollout:
- 0004_user_password.sql: Adds nullable `password_hash` and `password_salt`.
- Backfill existing users with passwords before enabling strict auth.
- 0005_enforce_password_not_null.sql: Recreates `users` with NOT NULL constraints for password fields.
