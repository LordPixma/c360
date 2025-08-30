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

  it('auth/login works with valid user credentials', async () => {
    const mockDB = new MockD1();
    const env = { 
      DB: mockDB, 
      KV: new MockKV(), 
      DEV_LOGIN_ENABLED: 'true',
      JWT_SECRET: 'test-secret'
    } as any;
    
    // Add a user with password to the mock database
    mockDB.addUser({
      user_id: 'test-user-id',
      tenant_id: 'test-tenant-id',
      email: 'test@example.com',
      role: 'admin',
      password_hash: '71c9594f7fa041b69f7128245e78e08a89f869ca31ae2922888d30ae0909776c', // SHA256 of 'password123test-salt'
      password_salt: 'test-salt',
      created_at: new Date().toISOString()
    });
    
    const res = await worker.fetch(
      makeRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'test@example.com', password: 'password123' }),
        headers: { 'content-type': 'application/json' }
      }),
      env,
      {} as any
    );
    
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.token).toBeDefined();
    expect(data.user).toBeDefined();
    expect(data.user.email).toBe('test@example.com');
  });
});