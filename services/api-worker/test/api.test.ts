import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { MockD1 } from './utils/mockD1';
import { MockKV } from './utils/mockKV';

const token = 'testtoken';
const makeRequest = (path: string, init: RequestInit = {}) =>
  new Request(`http://localhost${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      ...(init.headers || {})
    }
  });

describe('api worker', () => {
  it('health endpoint works', async () => {
    const res = await worker.fetch(makeRequest('/health'), globalThis as any, {} as any);
    expect(res.status).toBe(200);
  const data = (await res.json()) as any;
    expect(data.status).toBe('ok');
  });

  it('tenants list returns array', async () => {
    const env = { DB: new MockD1(), KV: new MockKV(), API_TOKEN: token } as any;
    const res = await worker.fetch(makeRequest('/tenants'), env, {} as any);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
  });
});
