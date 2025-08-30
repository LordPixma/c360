import type { Env } from '../../src/index';
import { MockD1 } from './mockD1';
import { MockKV } from './mockKV';

// Response type interfaces for API endpoints
export interface TenantResponse {
  tenant_id: string;
  name: string;
  created_at: string;
}

export interface UserResponse {
  user_id: string;
  tenant_id: string;
  email: string;
  role: string;
  created_at: string;
}

export interface HealthResponse {
  status: string;
}

// Mock ExecutionContext for testing
export const createMockExecutionContext = (): ExecutionContext => ({
  waitUntil: () => {},
  passThroughOnException: () => {},
  props: {},
});

export const createMockEnv = (): Env => ({
  DB: new MockD1() as unknown as D1Database,
  KV: new MockKV() as unknown as KVNamespace,
  // Optional environment variables that might be undefined
  CORS_ORIGIN: undefined,
  CORS_ORIGINS: undefined,
  API_TOKEN: undefined,
  RL_WINDOW_SECONDS: undefined,
  RL_MAX_REQUESTS: undefined,
  RL_MAX_REQUESTS_AUTH: undefined,
  DEV_LOGIN_ENABLED: undefined,
});