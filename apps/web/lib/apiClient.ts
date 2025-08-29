export type ApiOptions = {
  method?: string;
  headers?: Record<string, string>;
  body?: any;
  credentials?: RequestCredentials;
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8787';

export async function api(path: string, opts: ApiOptions = {}, retries = 1) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: opts.method || 'GET',
    headers: { 'content-type': 'application/json', 'x-csrf': '1', ...(opts.headers || {}) },
    credentials: opts.credentials ?? 'include',
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    cache: 'no-store'
  });
  if (!res.ok && retries > 0 && res.status >= 500) return api(path, opts, retries - 1);
  return res;
}
