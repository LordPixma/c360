import React from 'react'
import { useIdentity } from '../context/IdentityContext'
import './AppHeader.scss'

export default function AppHeader() {
  const { identity: whoami, email, logout } = useIdentity()
  if (!whoami) return null
  const tenantLabel = whoami.admin ? 'Admin' : (whoami.tenant?.name || whoami.tenant?.tenant_id || 'Tenant')

  return (
    <div className="app-header">
      <div className="pill">
        <span className="dot" />
        <span className="label">
          {email ? (<><span className="email">{email}</span><span className="sep">·</span></>) : null}
          {tenantLabel}
        </span>
        <button className="link" onClick={logout}>Log out</button>
      </div>
    </div>
  )
}
