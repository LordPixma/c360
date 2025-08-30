import React, { useMemo, useState } from 'react'
import './LoginPage.scss'
import { apiGet } from '../lib/api'

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [token, setToken] = useState<string>(() => {
    if (typeof window === 'undefined') return ''
    try { return localStorage.getItem('c360_token') || '' } catch { return '' }
  })
  const [success, setSuccess] = useState<string | null>(null)

  const emailValid = useMemo(() => /.+@.+\..+/.test(email), [email])
  const canSubmit = useMemo(() => emailValid && password.length >= 8 && !loading, [emailValid, password, loading])

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      setSuccess(null)
      if (!emailValid) throw new Error('Please enter a valid email address')
      if (password.length < 8) throw new Error('Password must be at least 8 characters')
  if (!token) throw new Error('Provide an API token or tenant API key for now')
      // For now, we just probe a protected endpoint to validate the token/key.
      // Admin token: Bearer <API_TOKEN>
      // Tenant API key: Bearer t_<tenantId>.<secret>
  const tenants = await apiGet<any[]>('/tenants', token)
  try { localStorage.setItem('c360_token', token) } catch {}
      setSuccess(`Authenticated. Found ${tenants.length} tenant(s).`)
    } catch (err: any) {
      const msg = err?.message || 'Login failed'
      if (err?.status === 401) setError('Unauthorized: check your token or API key')
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
          <form onSubmit={onSubmit} className="form">
            <label>
              <span>Email</span>
              <input type="email" placeholder="you@company.com" value={email} onChange={e => setEmail(e.target.value)} required />
            </label>
            <label>
              <span>Password</span>
              <input type="password" placeholder="••••••••" value={password} onChange={e => setPassword(e.target.value)} required />
            </label>
            <label>
              <span>API Token or Key</span>
              <input type="text" placeholder="Paste API token or t_<tenantId>.<secret>" value={token} onChange={e => setToken(e.target.value)} />
              <small style={{ color: '#8aa4c9' }}>Example: t_123e4567-89ab-4cde-ffff-0123456789ab.abcd…</small>
            </label>
            {error && <div className="error" role="alert">{error}</div>}
            {success && <div className="success" role="status">{success}</div>}
            <button type="submit" disabled={!canSubmit} className="primary">
              {loading ? 'Signing in…' : 'Sign in'}
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
