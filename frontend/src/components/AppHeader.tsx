import React, { useEffect, useState } from 'react'
import { apiGet } from '../lib/api'
import './AppHeader.scss'

type Identity = { admin?: boolean; tenant?: { tenant_id: string; name?: string } }

export default function AppHeader() {
  const [whoami, setWhoami] = useState<Identity | null>(null)

  useEffect(() => {
    const tok = (() => {
      try { return localStorage.getItem('c360_token') || '' } catch { return '' }
    })()
    if (!tok) return
    apiGet<Identity>('/whoami', tok).then(setWhoami).catch(() => {})
  }, [])

  function onLogout() {
    try { localStorage.removeItem('c360_token') } catch {}
    window.location.reload()
  }

  if (!whoami) return null
  const label = whoami.admin
    ? 'Admin'
    : (whoami.tenant?.name || whoami.tenant?.tenant_id || 'Tenant')

  return (
    <div className="app-header">
      <div className="pill">
        <span className="dot" />
        <span className="label">{label}</span>
        <button className="link" onClick={onLogout}>Log out</button>
      </div>
    </div>
  )
}
