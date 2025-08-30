import React, { useMemo, useState } from 'react'
import './LoginPage.scss'

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const canSubmit = useMemo(() => email.length > 0 && password.length > 0 && !loading, [email, password, loading])

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      await new Promise(r => setTimeout(r, 600)) // placeholder
      // TODO: call backend auth
      alert('Logged in (stub)')
    } catch (err: any) {
      setError(err?.message || 'Login failed')
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
            {error && <div className="error" role="alert">{error}</div>}
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
