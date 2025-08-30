import React, { useEffect, useMemo, useRef, useState } from 'react'
import './LoginPage.scss'
import { apiGet, loginWithPassword } from '../lib/api'

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Token storage remains for now to keep existing flows working; will be removed once auth is finalized.
  const [token, setToken] = useState<string>(() => {
    if (typeof window === 'undefined') return ''
    try { return localStorage.getItem('c360_token') || '' } catch { return '' }
  })
  const [success, setSuccess] = useState<string | null>(null)
  const [touched, setTouched] = useState<{ email?: boolean; password?: boolean }>({})
  const lastSubmitRef = useRef<number>(0)
  const [tokenEnabled, setTokenEnabled] = useState(false)
  const [identity, setIdentity] = useState<any | null>(null)

  const emailValid = useMemo(() => /.+@.+\..+/.test(email), [email])
  const canSubmit = useMemo(() => {
    if (tokenEnabled) return !!token && !loading
    return emailValid && password.length >= 8 && !loading
  }, [emailValid, password, tokenEnabled, token, loading])

  async function probeIdentity(bearer?: string) {
    try {
      const who = await apiGet<any>('/whoami', bearer || token)
      setIdentity(who)
      return who
    } catch {
      return null
    }
  }

  function onLogout() {
    try { localStorage.removeItem('c360_token') } catch {}
    setToken('')
    setIdentity(null)
    setError(null)
    setSuccess(null)
    setTouched({})
    setTokenEnabled(false)
  }

  useEffect(() => {
    // Auto sign-in if we already have a token
    if (!token) return
    probeIdentity(token).then((who) => {
      if (who) setSuccess('You are signed in')
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
  const now = Date.now()
  if (now - (lastSubmitRef.current || 0) < 800) return
  lastSubmitRef.current = now
    setLoading(true)
    setError(null)
    try {
      setSuccess(null)
      // If token fallback is enabled, try using the token directly
      if (tokenEnabled) {
        if (!token) throw new Error('Enter an API token or tenant key')
        const tenants = await apiGet<any[]>('/tenants', token)
        try {
          localStorage.setItem('c360_token', token)
          if (email) localStorage.setItem('c360_email', email)
        } catch {}
        const who = await probeIdentity(token)
        setSuccess(`Authenticated. Found ${tenants.length} tenant(s).`)
        return
      }

      // Normal login path
      if (!emailValid) throw new Error('Please enter a valid email address')
      if (password.length < 8) throw new Error('Password must be at least 8 characters')

      let bearer: string | undefined
      try {
        bearer = await loginWithPassword(email, password)
      } catch (err: any) {
        if (err?.status === 401) throw new Error('Invalid email or password')
        // If auth service isn’t available (404) or a network error occurred, enable token fallback
        if (err?.status === 404 || !('status' in (err || {}))) {
          setTokenEnabled(true)
          setError('Login service unavailable. You can sign in using an API token or tenant key below.')
          return
        }
        throw err
      }
      try {
        if (bearer) localStorage.setItem('c360_token', bearer)
        localStorage.setItem('c360_email', email)
      } catch {}

      // Verify the token by hitting a protected endpoint
  const tenants = await apiGet<any[]>('/tenants', bearer)
  await probeIdentity(bearer)
  setSuccess(`Authenticated. Found ${tenants.length} tenant(s).`)
    } catch (err: any) {
      const msg = err?.message || 'Login failed'
      if (err?.status === 401) setError('Unauthorized: check your credentials or token')
      else if (err?.status === 429) setError('Too many requests. Please wait and try again')
      else setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="branding">
        <div className="brand-layer" />
        <div className="brand-content">
          <div className="logo">C360</div>
          <h1>Compliance, Elevated</h1>
          <p>Multi-tenant compliance management for modern organizations. Secure. Scalable. Audit-ready.</p>
          <ul>
            <li>Role-based access across tenants</li>
            <li>Evidence workflows and task automation</li>
            <li>Real-time dashboards and analytics</li>
          </ul>
        </div>
      </div>
      <div className="panel">
        <div className="panel-inner">
          <h2>Welcome back</h2>
          <p className="subtitle">Sign in to continue to your workspace</p>
          {identity ? (
            <div className="signed-in">
              <div className="top-row">
                <div>
                  <div className="small-label">Signed in</div>
                  <div className="who">
                    {identity.admin ? (
                      <span>Administrator</span>
                    ) : (
                      <span>
                        {identity?.user?.email ? `${identity.user.email} · ` : ''}
                        {identity?.tenant?.name || identity?.tenant?.tenant_id || 'Tenant'}
                      </span>
                    )}
                  </div>
                </div>
                <button type="button" className="secondary" onClick={onLogout}>Log out</button>
              </div>
            </div>
          ) : null}

          <form onSubmit={onSubmit} className="form" aria-disabled={!!identity}>
            <label>
              <span>Email</span>
              <input
                type="email"
                placeholder="you@company.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                onBlur={() => setTouched(t => ({ ...t, email: true }))}
                required
                aria-invalid={touched.email && !emailValid}
                disabled={!!identity}
              />
              {touched.email && !emailValid && (
                <small className="field-error">Enter a valid email address</small>
              )}
            </label>
            <label>
              <span>Password</span>
              <input
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                onBlur={() => setTouched(t => ({ ...t, password: true }))}
                required
                aria-invalid={touched.password && password.length < 8}
                disabled={!!identity}
              />
              {touched.password && password.length < 8 && (
                <small className="field-error">Password must be at least 8 characters</small>
              )}
            </label>
            {/* Token fallback field (auto-enabled if /auth/login is unavailable) */}
            <label>
              <span>API Token or Tenant Key {tokenEnabled ? '' : '(disabled until needed)'}</span>
              <input
                type="text"
                placeholder="Paste API token or t_<tenantId>.<secret>"
                value={token}
                onChange={e => setToken(e.target.value)}
        disabled={!tokenEnabled || !!identity}
        readOnly={!tokenEnabled || !!identity}
              />
              {!tokenEnabled && (
                <small className="field-hint">This will auto-enable if the login service is unavailable.</small>
              )}
            </label>
            {error && <div className="error" role="alert">{error}</div>}
            {success && <div className="success" role="status">{success}</div>}
      <button type="submit" disabled={!canSubmit || loading || !!identity} className="primary">
              {loading ? 'Signing in…' : tokenEnabled ? 'Sign in with token' : 'Sign in'}
            </button>
            <div className="help-row">
              <a href="#">Forgot password?</a>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
