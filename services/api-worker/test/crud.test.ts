import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { createMockEnv, createMockExecutionContext, TenantResponse, UserResponse } from './utils/mockTypes';

const make = (path: string, init?: RequestInit) => new Request(`http://localhost${path}`, init);

describe('tenants and users CRUD', () => {
  it('tenant CRUD happy path', async () => {
    const env = createMockEnv();
    const ctx = createMockExecutionContext();

    // list empty
    let res = await worker.fetch(make('/tenants'), env, ctx);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual([]);

    // create
    res = await worker.fetch(make('/tenants', { method: 'POST', body: JSON.stringify({ name: 'Acme' }), headers: { 'content-type': 'application/json' } }), env, ctx);
    expect(res.status).toBe(200);
    const created = (await res.json()) as TenantResponse;
    expect(created.name).toBe('Acme');
    const id = created.tenant_id;

    // get
    res = await worker.fetch(make(`/tenants/${id}`), env, ctx);
    expect(res.status).toBe(200);

    // patch
    res = await worker.fetch(make(`/tenants/${id}`, { method: 'PATCH', body: JSON.stringify({ name: 'Acme 2' }), headers: { 'content-type': 'application/json' } }), env, ctx);
    expect(res.status).toBe(200);
    const updated = (await res.json()) as TenantResponse;
    expect(updated.name).toBe('Acme 2');

    // pagination
    res = await worker.fetch(make('/tenants?limit=10&offset=0'), env, ctx);
    expect(res.status).toBe(200);
    const listPage = (await res.json()) as TenantResponse[];
    expect(Array.isArray(listPage)).toBe(true);

    // delete
    res = await worker.fetch(make(`/tenants/${id}`, { method: 'DELETE' }), env, ctx);
    expect(res.status).toBe(200);
    res = await worker.fetch(make(`/tenants/${id}`), env, ctx);
    expect(res.status).toBe(404);
  });

  it('user CRUD under tenant', async () => {
    const env = createMockEnv();
    const ctx = createMockExecutionContext();

    // create tenant
    let res = await worker.fetch(make('/tenants', { method: 'POST', body: JSON.stringify({ name: 'T' }), headers: { 'content-type': 'application/json' } }), env, ctx);
    const tenant = (await res.json()) as TenantResponse;
    const tid = tenant.tenant_id;

    // list empty
    res = await worker.fetch(make(`/tenants/${tid}/users`), env, ctx);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual([]);

    // create user
  // invalid email
  res = await worker.fetch(make(`/tenants/${tid}/users`, { method: 'POST', body: JSON.stringify({ email: 'bad' }), headers: { 'content-type': 'application/json' } }), env, ctx);
  expect(res.status).toBe(400);
  // invalid role
  res = await worker.fetch(make(`/tenants/${tid}/users`, { method: 'POST', body: JSON.stringify({ email: 'ok@ex.com', role: 'owner' }), headers: { 'content-type': 'application/json' } }), env, ctx);
  expect(res.status).toBe(400);
  // valid
  res = await worker.fetch(make(`/tenants/${tid}/users`, { method: 'POST', body: JSON.stringify({ email: 'a@ex.com', role: 'admin' }), headers: { 'content-type': 'application/json' } }), env, ctx);
    expect(res.status).toBe(200);
    const user = (await res.json()) as UserResponse;
    const uid = user.user_id;
    expect(user.email).toBe('a@ex.com');

    // get one
    res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`), env, ctx);
    expect(res.status).toBe(200);

    // patch
  // invalid email
  res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`, { method: 'PATCH', body: JSON.stringify({ email: 'nope' }), headers: { 'content-type': 'application/json' } }), env, ctx);
  expect(res.status).toBe(400);
  // invalid role
  res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`, { method: 'PATCH', body: JSON.stringify({ role: 'owner' }), headers: { 'content-type': 'application/json' } }), env, ctx);
  expect(res.status).toBe(400);
  // valid
  res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`, { method: 'PATCH', body: JSON.stringify({ role: 'member' }), headers: { 'content-type': 'application/json' } }), env, ctx);
    expect(res.status).toBe(200);
    const patched = (await res.json()) as UserResponse;
    expect(patched.role).toBe('member');

    // pagination
    res = await worker.fetch(make(`/tenants/${tid}/users?limit=5&offset=0`), env, ctx);
    expect(res.status).toBe(200);

    // delete
    res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`, { method: 'DELETE' }), env, ctx);
    expect(res.status).toBe(200);
    res = await worker.fetch(make(`/tenants/${tid}/users/${uid}`), env, ctx);
    expect(res.status).toBe(404);
  });

  it('returns 400/404 appropriately', async () => {
    const env = createMockEnv();
    const ctx = createMockExecutionContext();

    // POST tenant without body
    let res = await worker.fetch(make('/tenants', { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } }), env, ctx);
    expect(res.status).toBe(400);

    // Not found user
    res = await worker.fetch(make('/tenants/does-not-exist/users/unknown'), env, ctx);
    expect(res.status).toBe(404);
  });
});
