import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    pool: '@cloudflare/vitest-pool-workers',
    poolOptions: {
      workers: {
        miniflare: {
          compatibilityDate: '2024-08-21',
          compatibilityFlags: ['nodejs_compat'],
          bindings: {
            DB: { type: 'D1Database', databaseId: 'test-db' },
            KV: { type: 'KVNamespace', namespaceId: 'test-kv' }
          }
        },
      },
    },
    globals: true,
    env: {
      NODE_ENV: 'test'
    }
  }
});
