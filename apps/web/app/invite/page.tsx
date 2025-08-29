"use client";
import { useState } from 'react';
import { api } from '../../lib/apiClient';

export default function InviteAcceptPage() {
  const [token, setToken] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const res = await api('/invites/accept', { method: 'POST', body: { token, name, password } });
    if (!res.ok) { setError('Invalid or expired invite'); return; }
    location.href = '/(protected)/dashboard';
  }
  return (
    <main style={{ padding: 24 }}>
      <h1>Accept Invite</h1>
      <form onSubmit={submit} style={{ display: 'grid', gap: 12, maxWidth: 420 }}>
        <input placeholder="Invite token" value={token} onChange={e=>setToken(e.target.value)} />
        <input placeholder="Full name" value={name} onChange={e=>setName(e.target.value)} />
        <input placeholder="Password" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
        <button type="submit">Join</button>
        {error && <p style={{ color: 'crimson' }}>{error}</p>}
      </form>
    </main>
  );
}
