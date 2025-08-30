import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
  test: {
    pool: '@cloudflare/vitest-pool-workers',
    globals: true,
    env: { NODE_ENV: 'test' },
    poolOptions: {
      workers: {
        miniflare: {
          compatibilityDate: '2024-11-01',
          compatibilityFlags: ['export_commonjs_default']
        }
      }
    }
  }
});
