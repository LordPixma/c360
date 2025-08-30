import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { MockD1 } from './utils/mockD1';
import { MockKV } from './utils/mockKV';

const makeRequest = (path: string, init?: RequestInit) =>
  new Request(`http://localhost${path}`, init);

describe('auth endpoints', () => {
  it('auth/login requires DEV_LOGIN_ENABLED', async () => {
    const env = { DB: new MockD1(), KV: new MockKV() } as any;
    const res = await worker.fetch(
      makeRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'test@example.com', password: 'password123' }),
        headers: { 'content-type': 'application/json' }
      }),
      env,
      {} as any
    );
    expect(res.status).toBe(404); // Not found when DEV_LOGIN_ENABLED is not set
  });

  it('auth/login validates email and password format', async () => {
    const env = { DB: new MockD1(), KV: new MockKV(), DEV_LOGIN_ENABLED: 'true' } as any;
    
    // Test missing email
    let res = await worker.fetch(
      makeRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ password: 'password123' }),
        headers: { 'content-type': 'application/json' }
      }),
      env,
      {} as any
    );
    expect(res.status).toBe(400);

    // Test invalid email
    res = await worker.fetch(
      makeRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'invalid-email', password: 'password123' }),
        headers: { 'content-type': 'application/json' }
      }),
      env,
      {} as any
    );
    expect(res.status).toBe(400);

    // Test short password
    res = await worker.fetch(
      makeRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'test@example.com', password: 'short' }),
        headers: { 'content-type': 'application/json' }
      }),
      env,
      {} as any
    );
    expect(res.status).toBe(400);
  });

  it('auth/login returns 401 for non-existent user', async () => {
    const env = { DB: new MockD1(), KV: new MockKV(), DEV_LOGIN_ENABLED: 'true' } as any;
    
    const res = await worker.fetch(
      makeRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'nonexistent@example.com', password: 'password123' }),
        headers: { 'content-type': 'application/json' }
      }),
      env,
      {} as any
    );
    expect(res.status).toBe(401);
  });
});