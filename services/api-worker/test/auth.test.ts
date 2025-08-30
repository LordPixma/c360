import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { MockD1 } from './utils/mockD1';

const make = (path: string, init: RequestInit = {}) => new Request(`http://localhost${path}`, init);

describe('authentication (JWT)', () => {
  it('create user with password, login to get JWT, call whoami', async () => {
    const kv: any = {
      store: new Map<string, string>(),
      async get(key: string) { return this.store.get(key) ?? null; },
      async put(key: string, value: string) { this.store.set(key, value); }
    };
    const env: any = { DB: new MockD1(), KV: kv, API_TOKEN: 'admin', JWT_SECRET: 'secret' };

    // Create tenant (admin)
    let res = await worker.fetch(new Request('http://localhost/tenants', { method: 'POST', body: JSON.stringify({ name: 'T' }), headers: { 'content-type': 'application/json', authorization: 'Bearer admin' } }), env, {} as any);
    expect(res.status).toBe(200);
    const tenant = await res.json() as any;

    // Create user with password (admin)
    res = await worker.fetch(new Request(`http://localhost/tenants/${tenant.tenant_id}/users`, { method: 'POST', body: JSON.stringify({ email: 'a@ex.com', role: 'admin', password: 'password123' }), headers: { 'content-type': 'application/json', authorization: 'Bearer admin' } }), env, {} as any);
    expect(res.status).toBe(200);

    // Login (user)
    res = await worker.fetch(make('/auth/login', { method: 'POST', body: JSON.stringify({ email: 'a@ex.com', password: 'password123' }), headers: { 'content-type': 'application/json' } }), env, {} as any);
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(typeof data.token).toBe('string');

    // whoami with JWT
    const who = await worker.fetch(new Request('http://localhost/whoami', { headers: { authorization: `Bearer ${data.token}` } }), env, {} as any);
    expect(who.status).toBe(200);
    const whoData = await who.json() as any;
    expect(whoData.user.email).toBe('a@ex.com');
  });
});