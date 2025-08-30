import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { MockD1 } from './utils/mockD1';

const makeRequest = (path: string, init?: RequestInit) =>
  new Request(`http://localhost${path}`, init);

describe('authentication', () => {
  it('login with valid credentials', async () => {
    const env = { DB: new MockD1(), KV: new Map() } as any;
    
    // Test login endpoint
    const res = await worker.fetch(makeRequest('/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'test@example.com', password: 'password123' })
    }), env, {} as any);
    
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.api_key).toBeDefined();
    expect(data.tenant_id).toBeDefined();
  });

  it('get user info after login', async () => {
    const env = { DB: new MockD1(), KV: new Map() } as any;
    
    // Mock authentication token
    const who = await worker.fetch(makeRequest('/auth/whoami', {
      headers: { 'authorization': 'Bearer mock-token' }
    }), env, {} as any);
    
    expect(who.status).toBe(200);
    const whoData = await who.json() as any;
    expect(whoData.user_id).toBeDefined();
  });

  it('test multiple auth endpoints', async () => {
    const env = { DB: new MockD1(), KV: new Map() } as any;
    
    // Test endpoint A
    const resA = await worker.fetch(makeRequest('/auth/validate-token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: 'mock-token' })
    }), env, {} as any);
    
    expect(resA.status).toBe(200);
    const dataA = await resA.json() as any;
    expect(dataA.valid).toBe(true);
    
    // Test endpoint B
    const resB = await worker.fetch(makeRequest('/auth/refresh', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ refresh_token: 'mock-refresh-token' })
    }), env, {} as any);
    
    expect(resB.status).toBe(200);
    const dataB = await resB.json() as any;
    expect(dataB.access_token).toBeDefined();
  });

  it('list users with authentication', async () => {
    const env = { DB: new MockD1(), KV: new Map() } as any;
    
    // Test authenticated user listing
    const listB = await worker.fetch(makeRequest('/auth/users', {
      headers: { 'authorization': 'Bearer mock-admin-token' }
    }), env, {} as any);
    
    expect(listB.status).toBe(200);
    const usersB = await listB.json() as any[];
    expect(Array.isArray(usersB)).toBe(true);
  });
});