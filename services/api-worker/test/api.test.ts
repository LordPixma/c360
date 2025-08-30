import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { MockD1 } from './utils/mockD1';

const makeRequest = (path: string, init: RequestInit = {}) => {
  const headers = new Headers(init.headers || {});
  headers.set('authorization', 'Bearer admin');
  return new Request(`http://localhost${path}`, { ...init, headers });
};

describe('api worker', () => {
  it('health endpoint works', async () => {
    const res = await worker.fetch(makeRequest('/health'), globalThis as any, {} as any);
    expect(res.status).toBe(200);
  const data = (await res.json()) as any;
    expect(data.status).toBe('ok');
  });

  it('tenants list returns array', async () => {
    const kv: any = {
      store: new Map<string, string>(),
      async get(key: string) { return this.store.get(key) ?? null; },
      async put(key: string, value: string) { this.store.set(key, value); }
    };
    const env = { DB: new MockD1(), KV: kv, API_TOKEN: 'admin' } as any;
    const res = await worker.fetch(makeRequest('/tenants'), env, {} as any);
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(Array.isArray(data)).toBe(true);
  });
});
