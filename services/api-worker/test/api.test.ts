import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { createMockEnv, createMockExecutionContext, HealthResponse } from './utils/mockTypes';

const makeRequest = (path: string, init?: RequestInit) =>
  new Request(`http://localhost${path}`, init);

describe('api worker', () => {
  it('health endpoint works', async () => {
    const env = createMockEnv();
    const ctx = createMockExecutionContext();
    const res = await worker.fetch(makeRequest('/health'), env, ctx);
    expect(res.status).toBe(200);
    const data = (await res.json()) as HealthResponse;
    expect(data.status).toBe('ok');
  });

  it('tenants list returns array', async () => {
    const env = createMockEnv();
    const ctx = createMockExecutionContext();
    const res = await worker.fetch(makeRequest('/tenants'), env, ctx);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
  });
});
