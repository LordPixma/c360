export const API_BASE: string = (import.meta as any).env?.VITE_API_BASE || 'http://127.0.0.1:8787'

export type ApiError = {
  status: number
  message: string
  code?: string
}

async function parseJsonSafe(res: Response): Promise<any | null> {
  try {
    return await res.json()
  } catch {
    return null
  }
}

function normalizeAuthToken(token?: string): string | undefined {
  if (!token) return undefined
  const t = token.trim()
  if (/^bearer\s+/i.test(t)) return t.replace(/^bearer\s+/i, '').trim()
  return t
}

export async function apiGet<T = unknown>(path: string, token?: string): Promise<T> {
  const raw = normalizeAuthToken(token)
  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: 'GET',
      headers: {
        ...(raw ? { Authorization: `Bearer ${raw}` } : {}),
        'accept': 'application/json'
      },
      credentials: 'include'
    })
  } catch (e: any) {
    const err: ApiError = { status: 0, message: 'Network error: cannot reach API', code: 'network_error' }
    throw err
  }
  if (!res.ok) {
    const data = await parseJsonSafe(res)
    const msg = (data?.error?.message as string) || res.statusText || 'Request failed'
    const code = (data?.error?.code as string) || undefined
    const err: ApiError = { status: res.status, message: msg, code }
    throw err
  }
  return (await res.json()) as T
}

// Placeholder for a future username/password auth flow
export async function loginWithPassword(email: string, password: string): Promise<string> {
  let res: Response
  try {
    res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'accept': 'application/json'
      },
      body: JSON.stringify({ email, password }),
      credentials: 'include'
    })
  } catch (e: any) {
    const err: ApiError = { status: 0, message: 'Network error: cannot reach login service', code: 'network_error' }
    throw err
  }
  if (!res.ok) {
    const data = await parseJsonSafe(res)
    const msg = (data?.error?.message as string) || res.statusText || 'Login failed'
    const code = (data?.error?.code as string) || undefined
    const err: ApiError = { status: res.status, message: msg, code }
    throw err
  }
  const data = await res.json()
  const token: string | undefined = data?.token || data?.api_key
  if (!token) throw new Error('Missing token in response')
  return token
}
