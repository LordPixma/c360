import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { MockD1 } from './utils/mockD1';

const make = (path: string, init: RequestInit = {}) => {
  const headers = new Headers(init.headers || {});
  headers.set('authorization', 'Bearer admin');
  return new Request(`http://localhost${path}`, { ...init, headers });
};

describe('tenants and users CRUD', () => {
  it('tenant CRUD happy path', async () => {
    const kv: any = {
      store: new Map<string, string>(),
      async get(key: string) { return this.store.get(key) ?? null; },
      async put(key: string, value: string) { this.store.set(key, value); }
    };
  const env: any = { DB: new MockD1(), KV: kv, API_TOKEN: 'admin', JWT_SECRET: 'secret' };

    // list empty
    let res = await worker.fetch(make('/tenants'), env, {} as any);
    expect(res.status).toBe(200);
    expect(await res.json() as any).toEqual([]);

    // create
    res = await worker.fetch(make('/tenants', { method: 'POST', body: JSON.stringify({ name: 'Acme' }), headers: { 'content-type': 'application/json' } }), env, {} as any);
    expect(res.status).toBe(200);
    const created = (await res.json()) as any;
    expect(created.name).toBe('Acme');
    const id = created.tenant_id;

    // get
    res = await worker.fetch(make(`/tenants/${id}`), env, {} as any);
    expect(res.status).toBe(200);

    // patch
    res = await worker.fetch(make(`/tenants/${id}`, { method: 'PATCH', body: JSON.stringify({ name: 'Acme 2' }), headers: { 'content-type': 'application/json' } }), env, {} as any);
    expect(res.status).toBe(200);
    const updated = (await res.json()) as any;
    expect(updated.name).toBe('Acme 2');

    // pagination
    res = await worker.fetch(make('/tenants?limit=10&offset=0'), env, {} as any);
    expect(res.status).toBe(200);
    const listPage = (await res.json()) as any[];
    expect(Array.isArray(listPage)).toBe(true);

    // delete
    res = await worker.fetch(make(`/tenants/${id}`, { method: 'DELETE' }), env, {} as any);
    expect(res.status).toBe(200);
    res = await worker.fetch(make(`/tenants/${id}`), env, {} as any);
    expect(res.status).toBe(404);
  });

  it('user CRUD under tenant', async () => {
    const kv2: any = {
      store: new Map<string, string>(),
      async get(key: string) { return this.store.get(key) ?? null; },
      async put(key: string, value: string) { this.store.set(key, value); }
    };
  const env: any = { DB: new MockD1(), KV: kv2, API_TOKEN: 'admin', JWT_SECRET: 'secret' };

    // create tenant
    let res = await worker.fetch(make('/tenants', { method: 'POST', body: JSON.stringify({ name: 'T' }), headers: { 'content-type': 'application/json' } }), env, {} as any);
    const tenant = (await res.json()) as any;
    const tid = tenant.tenant_id;

    // list empty
    res = await worker.fetch(make(`/tenants/${tid}/users`), env, {} as any);
    expect(res.status).toBe(200);
    expect(await res.json() as any).toEqual([]);

    // create user
  // invalid email
  res = await worker.fetch(make(`/tenants/${tid}/users`, { method: 'POST', body: JSON.stringify({ email: 'bad', password: 'password123' }), headers: { 'content-type': 'application/json' } }), env, {} as any);
  expect(res.status).toBe(400);
  // invalid role
  res = await worker.fetch(make(`/tenants/${tid}/users`, { method: 'POST', body: JSON.stringify({ email: 'ok@ex.com', role: 'owner', password: 'password123' }), headers: { 'content-type': 'application/json' } }), env, {} as any);
  expect(res.status).toBe(400);
  // valid
  res = await worker.fetch(make(`/tenants/${tid}/users`, { method: 'POST', body: JSON.stringify({ email: 'a@ex.com', role: 'admin', password: 'password123' }), headers: { 'content-type': 'application/json' } }), env, {} as any);
    expect(res.status).toBe(200);
    const user = (await res.json()) as any;
    const uid = user.user_id;
    expect(user.email).toBe('a@ex.com');

    // get one
    res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`), env, {} as any);
    expect(res.status).toBe(200);

    // patch
  // invalid email
  res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`, { method: 'PATCH', body: JSON.stringify({ email: 'nope' }), headers: { 'content-type': 'application/json' } }), env, {} as any);
  expect(res.status).toBe(400);
  // invalid role
  res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`, { method: 'PATCH', body: JSON.stringify({ role: 'owner' }), headers: { 'content-type': 'application/json' } }), env, {} as any);
  expect(res.status).toBe(400);
  // valid
  res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`, { method: 'PATCH', body: JSON.stringify({ role: 'member' }), headers: { 'content-type': 'application/json' } }), env, {} as any);
    expect(res.status).toBe(200);
    const patched = (await res.json()) as any;
    expect(patched.role).toBe('member');

    // pagination
    res = await worker.fetch(make(`/tenants/${tid}/users?limit=5&offset=0`), env, {} as any);
    expect(res.status).toBe(200);

    // delete
    res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`, { method: 'DELETE' }), env, {} as any);
    expect(res.status).toBe(200);
    res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`), env, {} as any);
    expect(res.status).toBe(404);
  });

  it('returns 400/404 appropriately', async () => {
    const kv3: any = {
      store: new Map<string, string>(),
      async get(key: string) { return this.store.get(key) ?? null; },
      async put(key: string, value: string) { this.store.set(key, value); }
    };
  const env: any = { DB: new MockD1(), KV: kv3, API_TOKEN: 'admin', JWT_SECRET: 'secret' };

    // POST tenant without body
    let res = await worker.fetch(make('/tenants', { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } }), env, {} as any);
    expect(res.status).toBe(400);

    // Not found user
    res = await worker.fetch(make('/tenants/does-not-exist/users/unknown'), env, {} as any);
    expect(res.status).toBe(404);
  });
});
