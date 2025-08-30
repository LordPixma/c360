import { MockD1 } from './mockD1';
import { MockKV } from './mockKV';

// Shared mock environment setup to reduce duplication
export function createMockEnv() {
  return {
    DB: new MockD1(),
    KV: new MockKV(),
    API_TOKEN: 'test-token'
  } as any;
}

// Helper for making authenticated requests
export function makeAuthenticatedRequest(path: string, init?: RequestInit): Request {
  const headers = new Headers(init?.headers);
  headers.set('authorization', 'Bearer test-token');
  
  return new Request(`http://localhost${path}`, {
    ...init,
    headers
  });
}