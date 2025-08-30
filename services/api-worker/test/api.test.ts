import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { MockD1 } from './utils/mockD1';

const makeRequest = (path: string, init?: RequestInit) => {
  const headers = new Headers(init?.headers);
  headers.set('Authorization', 'Bearer testtoken');
  return new Request(`http://localhost${path}`, { ...init, headers });
};

const makeEnv = () => {
  const store = new Map<string, string>();
  return {
    DB: new MockD1(),
    KV: {
      get: (k: string) => Promise.resolve(store.get(k) || null),
      put: (k: string, v: string) => {
        store.set(k, v);
        return Promise.resolve();
      }
    },
    API_TOKEN: 'testtoken'
  } as any;
};

describe('api worker', () => {
  it('health endpoint works', async () => {
    const res = await worker.fetch(makeRequest('/health'), globalThis as any, {} as any);
    expect(res.status).toBe(200);
  const data = (await res.json()) as any;
    expect(data.status).toBe('ok');
  });

  it('tenants list returns array', async () => {
    const env = makeEnv();
    const res = await worker.fetch(makeRequest('/tenants'), env, {} as any);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
  });
});
