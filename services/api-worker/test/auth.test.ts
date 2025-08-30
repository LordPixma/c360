import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { MockD1 } from './utils/mockD1';
import { MockKV } from './utils/mockKV';

const make = (path: string, init: RequestInit = {}) => new Request(`http://localhost${path}`, init);

describe('authentication and access control', () => {
  it('login returns api key and allows authenticated access', async () => {
    const env: any = { DB: new MockD1(), KV: new MockKV(), DEV_LOGIN_ENABLED: 'true' };
    const res = await worker.fetch(
      make('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'user@example.com', password: 'password123' }),
        headers: { 'content-type': 'application/json' }
      }),
      env,
      {} as any
    );
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.api_key).toBeTruthy();
    expect(data.tenant_id).toBeTruthy();

    const who = await worker.fetch(
      make('/whoami', { headers: { authorization: `Bearer ${data.api_key}` } }),
      env,
      {} as any
    );
    expect(who.status).toBe(200);
    const whoData = await who.json();
    expect(whoData.tenant.tenant_id).toBe(data.tenant_id);
  });

  it('login rejects invalid credentials', async () => {
    const env: any = { DB: new MockD1(), KV: new MockKV(), DEV_LOGIN_ENABLED: 'true' };
    let res = await worker.fetch(
      make('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'bad', password: 'password123' }),
        headers: { 'content-type': 'application/json' }
      }),
      env,
      {} as any
    );
    expect(res.status).toBe(400);
    res = await worker.fetch(
      make('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'user@example.com', password: 'short' }),
        headers: { 'content-type': 'application/json' }
      }),
      env,
      {} as any
    );
    expect(res.status).toBe(400);
  });

  it('enforces token-based access control', async () => {
    const env: any = { DB: new MockD1(), KV: new MockKV() };
    let res = await worker.fetch(make('/whoami'), env, {} as any);
    expect(res.status).toBe(401);
    res = await worker.fetch(make('/whoami', { headers: { authorization: 'Bearer badtoken' } }), env, {} as any);
    expect(res.status).toBe(401);
    env.API_TOKEN = 'admintoken';
    res = await worker.fetch(make('/whoami', { headers: { authorization: 'Bearer admintoken' } }), env, {} as any);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.admin).toBe(true);
  });

  it('isolates tenants by api key', async () => {
    const env: any = { DB: new MockD1(), KV: new MockKV(), DEV_LOGIN_ENABLED: 'true' };
    // tenant A
    const resA = await worker.fetch(
      make('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'a@example.com', password: 'password123' }),
        headers: { 'content-type': 'application/json' }
      }),
      env,
      {} as any
    );
    const dataA = await resA.json();
    // tenant B
    const resB = await worker.fetch(
      make('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'b@example.com', password: 'password123' }),
        headers: { 'content-type': 'application/json' }
      }),
      env,
      {} as any
    );
    const dataB = await resB.json();

    // create user for tenant A
    await worker.fetch(
      make(`/tenants/${dataA.tenant_id}/users`, {
        method: 'POST',
        body: JSON.stringify({ email: 'new@a.com', role: 'member' }),
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${dataA.api_key}`
        }
      }),
      env,
      {} as any
    );

    // list users for tenant B should not include tenant A's user
    const listB = await worker.fetch(
      make(`/tenants/${dataB.tenant_id}/users`, {
        headers: { authorization: `Bearer ${dataB.api_key}` }
      }),
      env,
      {} as any
    );
    expect(listB.status).toBe(200);
    const usersB = (await listB.json()) as any[];
    expect(Array.isArray(usersB)).toBe(true);
    expect(usersB.every((u: any) => u.tenant_id === dataB.tenant_id)).toBe(true);
  });
});
