import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { MockD1 } from './utils/mockD1';

const makeRequest = (path: string, init?: RequestInit) =>
  new Request(`http://localhost${path}`, init);

describe('api worker', () => {
  it('health endpoint works', async () => {
    const res = await worker.fetch(makeRequest('/health'), globalThis as any, {} as any);
    expect(res.status).toBe(200);
  const data = (await res.json()) as any;
    expect(data.status).toBe('ok');
  });

  it('tenants list returns array', async () => {
    const kv = new Map<string, string>();
    const env = { DB: new MockD1(), KV: { get: async (k: string) => kv.get(k) ?? null, put: async (k: string, v: string) => { kv.set(k, v); } }, API_TOKEN: 'admintoken', JWT_SECRET: 'secret' } as any;
    const res = await worker.fetch(makeRequest('/tenants', { headers: { authorization: 'Bearer admintoken' } }), env, {} as any);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
  });

  it('login returns JWT for valid credentials', async () => {
    const kv = new Map<string, string>();
    const env: any = { DB: new MockD1(), KV: { get: async (k: string) => kv.get(k) ?? null, put: async (k: string, v: string) => { kv.set(k, v); } }, API_TOKEN: 'admintoken', JWT_SECRET: 'secret' };
    // create tenant
    let res = await worker.fetch(makeRequest('/tenants', { method: 'POST', body: JSON.stringify({ name: 'T' }), headers: { 'content-type': 'application/json', authorization: 'Bearer admintoken' } }), env, {} as any);
    const tenant = await res.json() as any;
    // create user with password
    res = await worker.fetch(makeRequest(`/tenants/${tenant.tenant_id}/users`, { method: 'POST', body: JSON.stringify({ email: 'a@ex.com', role: 'admin', password: 'password123' }), headers: { 'content-type': 'application/json', authorization: 'Bearer admintoken' } }), env, {} as any);
    expect(res.status).toBe(200);
    // login
    res = await worker.fetch(makeRequest('/auth/login', { method: 'POST', body: JSON.stringify({ email: 'a@ex.com', password: 'password123' }), headers: { 'content-type': 'application/json' } }), env, {} as any);
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(typeof data.token).toBe('string');
    // whoami with token
    res = await worker.fetch(makeRequest('/whoami', { headers: { authorization: `Bearer ${data.token}` } }), env, {} as any);
    expect(res.status).toBe(200);
    const who = await res.json() as any;
    expect(who.user.email).toBe('a@ex.com');
  });
});
