"use client";
import { useState } from 'react';
import { api } from '../../../lib/apiClient';

export default function ResetConfirmPage() {
  const [token, setToken] = useState('');
  const [password, setPassword] = useState('');
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setError(null);
    const res = await api('/auth/reset/confirm', { method: 'POST', body: { token, password } });
    if (!res.ok) { setError('Invalid or expired token'); return; }
    setDone(true);
  }
  return (
    <main style={{ padding: 24 }}>
      <h1>Set new password</h1>
      {done ? <p>Password updated. You can now sign in.</p> : (
        <form onSubmit={submit} style={{ display: 'grid', gap: 12, maxWidth: 420 }}>
          <input placeholder="Reset token" value={token} onChange={e=>setToken(e.target.value)} />
          <input placeholder="New password" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
          <button type="submit">Update</button>
          {error && <p style={{ color: 'crimson' }}>{error}</p>}
        </form>
      )}
    </main>
  );
}
