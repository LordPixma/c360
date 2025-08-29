# Comp360Flow - Multi-Tenant Compliance Management Platform

**ALWAYS follow these instructions first** and only fallback to additional search and context gathering if the information here is incomplete or found to be in error.

Comp360Flow is a Cloudflare-native multi-tenant SaaS platform for compliance management, built with Next.js, Cloudflare Workers, and D1 database. The platform supports multiple compliance frameworks (SOC 2, ISO 27001, GDPR, PCI DSS, HIPAA, SOX) with tenant isolation and role-based access control.

## Repository Structure

```
apps/web          — Next.js frontend (Next on Pages)
services/api-worker — Cloudflare Worker API backend  
services/queue-consumers — Background job processing
packages/core-domain — Shared domain logic
packages/cf-bindings — Cloudflare environment typings
packages/ui       — Shared UI components
infra/migrations  — D1 database schema migrations
catalogs/         — Framework/control seed data
```

## Working Effectively

### Bootstrap and Install Dependencies
```bash
# Install all workspace dependencies
npm install
# Time: ~25 seconds first time, ~2 seconds subsequent. NEVER CANCEL. Set timeout to 60+ seconds.
```

### Build Commands
```bash
# Build web app (Next.js only - working)
cd apps/web && npx next build
# Time: ~15 seconds. NEVER CANCEL. Set timeout to 45+ seconds.

# TypeScript compilation check for API worker
cd services/api-worker && npx tsc --noEmit  
# Time: ~2 seconds. Quick validation.

# WARNING: Full next-on-pages build currently fails due to recursive invocation
# cd apps/web && npm run build  # DO NOT USE - causes recursive build error
```

### Development Workflow
```bash
# 1. Start API Worker (always start this first)
cd services/api-worker && npx wrangler dev --local
# Starts on http://localhost:8787
# Time: ~5 seconds to start. NEVER CANCEL.

# 2. Start Web App (in separate terminal)
cd apps/web && NEXT_PUBLIC_API_BASE_URL=http://localhost:8787 npm run dev
# Starts on http://localhost:3000  
# Time: ~5 seconds to start. NEVER CANCEL.
```

### Database Setup
The application uses Cloudflare D1 database with local development support:
```bash
# Database runs automatically with wrangler dev --local
# Migrations are in infra/migrations/
# No manual setup required for local development
```

## Validation

### ALWAYS Validate After Changes
1. **Health Check API**: `curl http://localhost:8787/health` should return `{"ok":true,"service":"api","ts":<timestamp>}`
2. **Web App Homepage**: `curl http://localhost:3000` should return HTML with "Comp360Flow" title
3. **Sign-in Page**: `curl http://localhost:3000/signin` should return sign-in form HTML
4. **TypeScript Compilation**: Run `npx tsc --noEmit` in both `apps/web` and `services/api-worker`

### Manual Testing Scenarios
- **Homepage Flow**: Visit http://localhost:3000, verify "Sign in" and "Create account" links
- **Authentication Pages**: Test /signin, /signup, /reset routes load correctly
- **API Communication**: Ensure web app can communicate with API worker on port 8787
- **Service Startup**: Both services should start without errors and respond to requests

## Critical Timing Information

- **npm install**: 25 seconds first time, 2 seconds subsequent - NEVER CANCEL, use 60+ second timeout
- **Next.js build**: 15 seconds - NEVER CANCEL, use 45+ second timeout  
- **Service startup**: 5 seconds each - NEVER CANCEL, use 30+ second timeout
- **TypeScript compilation**: 2 seconds - quick validation

## Known Issues and Workarounds

### Build Issues
- **next-on-pages build fails**: Use `npx next build` instead of `npm run build` for web app
- **Recursive invocation error**: The next-on-pages integration has a configuration issue
- **Cloudflare API tokens**: Wrangler operations requiring remote access will fail in CI/sandboxed environments

### Development Environment
- **No test infrastructure**: Repository has no test files or test scripts configured
- **No linting**: No ESLint or Prettier configuration present
- **Local D1 database**: Automatically managed by wrangler dev --local

## Environment Variables

### Web App (apps/web/.env.local)
```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8787
NEXT_PUBLIC_TURNSTILE_SITE_KEY=<optional-for-dev>
```

### API Worker
Uses wrangler.toml configuration:
- D1 Database binding: `DB` (local: c360_dev)
- Queue binding: `EMAIL_QUEUE` (c360-email)
- Variables set via `wrangler secret put` or environment

## Key Files and Locations

### Frequently Modified Files
- `apps/web/app/` - Next.js app router pages
- `services/api-worker/src/index.ts` - Main API worker logic
- `infra/migrations/` - Database schema changes
- `packages/core-domain/src/` - Shared business logic

### Configuration Files
- `wrangler.toml` - Root placeholder, actual configs in service directories
- `services/api-worker/wrangler.toml` - API worker configuration
- `apps/web/next.config.mjs` - Next.js configuration
- `package.json` - Root workspace configuration

### Database Schema
- **Primary tables**: tenants, users, branding
- **Authentication**: auth_events, password_reset_tokens, recovery_codes  
- **Multi-tenancy**: tenant_domains, invites
- **Auditing**: audit_log

## Common Tasks

### Adding New API Endpoints
1. Edit `services/api-worker/src/index.ts`
2. Run `npx tsc --noEmit` to check TypeScript
3. Test with wrangler dev and curl commands

### Modifying Frontend Pages
1. Edit files in `apps/web/app/`
2. Changes hot-reload automatically in dev mode
3. Test by visiting the page in browser

### Database Changes
1. Create new migration file in `infra/migrations/`
2. Follow naming convention: `000N_description.sql`
3. Use SQLite syntax compatible with D1

## Quick Reference Commands

```bash
# Full development setup (run in order)
npm install                                           # 25s first/2s subsequent - NEVER CANCEL
cd services/api-worker && npx wrangler dev --local    # Start API (port 8787)
cd apps/web && NEXT_PUBLIC_API_BASE_URL=http://localhost:8787 npm run dev  # Start web (port 3000)

# Validation commands
curl http://localhost:8787/health                     # API health check
curl http://localhost:3000                            # Web app check
cd apps/web && npx tsc --noEmit                       # TypeScript check
cd services/api-worker && npx tsc --noEmit            # API TypeScript check

# Build commands (for production)
cd apps/web && npx next build                         # 15s - NEVER CANCEL
```

Always ensure both services are running before testing the application functionality. The web app depends on the API worker for backend operations.