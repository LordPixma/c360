"use client";
import { useState } from 'react';
import { api } from '../../lib/apiClient';

export default function ResetRequestPage() {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    await api('/auth/reset/request', { method: 'POST', body: { email } });
    setSent(true);
  }
  return (
    <main style={{ padding: 24 }}>
      <h1>Password reset</h1>
      {sent ? <p>Check your email for a reset link (token shown in dev).</p> : (
        <form onSubmit={submit} style={{ display: 'grid', gap: 12, maxWidth: 420 }}>
          <input placeholder="you@company.com" value={email} onChange={e=>setEmail(e.target.value)} />
          <button type="submit">Send reset link</button>
        </form>
      )}
    </main>
  );
}
