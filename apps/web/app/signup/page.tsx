"use client";

import { useState } from 'react';
import { api } from '../../lib/apiClient';

export default function SignUpPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    const form = new FormData(e.currentTarget);
    const name = String(form.get('name') || '');
    const email = String(form.get('email') || '');
    const company = String(form.get('company') || '');
    let cfTurnstileToken: string | undefined;
    try {
      // @ts-ignore
      cfTurnstileToken = typeof turnstile !== 'undefined' ? await new Promise<string>((resolve) => {
        // @ts-ignore
        turnstile.render('#cf-turnstile', {
          sitekey: siteKey,
          callback: (t: string) => resolve(t)
        });
      }) : undefined;
    } catch {}

  const res = await api('/auth/signup', { method: 'POST', body: { name, email, company, cfTurnstileToken } });
    setLoading(false);
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      setError(data?.error || 'Signup failed');
      return;
    }
    location.href = '/(protected)/dashboard';
  }

  return (
    <main style={{ padding: 24, fontFamily: 'system-ui' }}>
      <h1>Create your account</h1>
      <form onSubmit={onSubmit} style={{ display: 'grid', gap: 12, maxWidth: 420 }}>
        <input type="text" name="name" placeholder="Full name" required />
        <input type="email" name="email" placeholder="you@company.com" required />
        <input type="text" name="company" placeholder="Company name" required />
        <div id="cf-turnstile" />
        <button type="submit" disabled={loading}>{loading ? 'Creating…' : 'Sign up'}</button>
        {error && <p style={{ color: 'crimson' }}>{error}</p>}
      </form>
      {siteKey && <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" defer></script>}
    </main>
  );
}
