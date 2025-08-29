"use client";
import { useState } from 'react';
import { api } from '../../../lib/apiClient';

export default function MfaSetupPage() {
  const [url, setUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function setup() {
    setError(null);
    const res = await api('/auth/mfa/setup', { method: 'POST' });
    if (!res.ok) { setError('Failed to setup'); return; }
    const data = await res.json();
    setUrl(data?.otpauth || null);
  }
  return (
    <main style={{ padding: 24 }}>
      <h1>MFA Setup</h1>
      <button onClick={setup}>Generate TOTP Secret</button>
      {error && <p style={{ color: 'crimson' }}>{error}</p>}
      {url && <p>Scan in your authenticator: <code>{url}</code></p>}
    </main>
  );
}
