import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { apiGet } from '../lib/api'

export type Identity = {
  admin?: boolean
  tenant?: { tenant_id: string; name?: string }
}

type Ctx = {
  identity: Identity | null
  email: string
  token: string
  loading: boolean
  error: string | null
  refresh: () => Promise<void>
  setToken: (t: string) => void
  logout: () => void
}

const IdentityContext = createContext<Ctx | undefined>(undefined)

export function IdentityProvider({ children }: { children: React.ReactNode }) {
  const [identity, setIdentity] = useState<Identity | null>(null)
  const [email, setEmail] = useState<string>(() => {
    try { return localStorage.getItem('c360_email') || '' } catch { return '' }
  })
  const [token, setTokenState] = useState<string>(() => {
    try { return localStorage.getItem('c360_token') || '' } catch { return '' }
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inFlight = useRef<Promise<void> | null>(null)

  const setToken = useCallback((t: string) => {
    setTokenState(t)
    try { t ? localStorage.setItem('c360_token', t) : localStorage.removeItem('c360_token') } catch {}
  }, [])

  const logout = useCallback(() => {
    setToken('')
    setIdentity(null)
    setError(null)
    setLoading(false)
    try { localStorage.removeItem('c360_email') } catch {}
  }, [setToken])

  const refresh = useCallback(async () => {
    if (!token) {
      setIdentity(null)
      setError(null)
      return
    }
    if (inFlight.current) return inFlight.current
    const p = (async () => {
      setLoading(true)
      setError(null)
      try {
        const who = await apiGet<Identity>('/whoami', token)
        setIdentity(who || null)
        setEmail(() => { try { return localStorage.getItem('c360_email') || '' } catch { return '' } })
      } catch (e: any) {
        setIdentity(null)
        // Keep token but surface a soft error
        setError(e?.message || 'Failed to fetch identity')
      } finally {
        setLoading(false)
        inFlight.current = null
      }
    })()
    inFlight.current = p
    return p
  }, [token])

  // Route change listener: popstate, hashchange, pushState/replaceState hooks
  useEffect(() => {
    const navEvent = 'app:navigate'
    const origPush = history.pushState
    const origReplace = history.replaceState
    // @ts-ignore
    history.pushState = function (...args) { const r = origPush.apply(this, args as any); window.dispatchEvent(new Event(navEvent)); return r }
    // @ts-ignore
    history.replaceState = function (...args) { const r = origReplace.apply(this, args as any); window.dispatchEvent(new Event(navEvent)); return r }

    const onChange = () => { refresh() }
    window.addEventListener('popstate', onChange)
    window.addEventListener('hashchange', onChange)
    window.addEventListener(navEvent, onChange)
    return () => {
      history.pushState = origPush
      history.replaceState = origReplace
      window.removeEventListener('popstate', onChange)
      window.removeEventListener('hashchange', onChange)
      window.removeEventListener(navEvent, onChange)
    }
  }, [refresh])

  // Initial fetch on mount and when token changes
  useEffect(() => { refresh() }, [refresh])

  const value = useMemo<Ctx>(() => ({ identity, email, token, loading, error, refresh, setToken, logout }), [identity, email, token, loading, error, refresh, setToken, logout])
  return <IdentityContext.Provider value={value}>{children}</IdentityContext.Provider>
}

export function useIdentity() {
  const ctx = useContext(IdentityContext)
  if (!ctx) throw new Error('useIdentity must be used within IdentityProvider')
  return ctx
}
