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
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'GET',
    headers: {
      ...(raw ? { Authorization: `Bearer ${raw}` } : {}),
      'accept': 'application/json'
    }
  })
  if (!res.ok) {
    const data = await parseJsonSafe(res)
    const msg = (data?.error?.message as string) || res.statusText || 'Request failed'
    const code = (data?.error?.code as string) || undefined
    const err: ApiError = { status: res.status, message: msg, code }
    throw err
  }
  return (await res.json()) as T
}
