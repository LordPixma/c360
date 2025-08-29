# Cloudflare Monorepo Scaffold

This repo hosts a Cloudflare-native multi-tenant SaaS (Comp360Flow).

Structure:
- apps/web — frontend (Next on Pages or Hono SSR)
- services/api-worker — API Worker
- services/queue-consumers — background jobs
- packages/core-domain — shared domain logic
- packages/cf-bindings — Cloudflare env typings and utilities
- packages/ui — shared UI components
- infra — Wrangler config, D1 migrations, Access policies, Terraform (optional)
- catalogs — framework/control seed data
