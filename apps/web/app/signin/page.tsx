"use client";

import { useState } from 'react';
import { api } from '../../lib/apiClient';

export default function SignInPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const siteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    const form = new FormData(e.currentTarget);
    const email = String(form.get('email') || '');
    const password = String(form.get('password') || '');
    let cfTurnstileToken: string | undefined;
    try {
      // Turnstile widget optional in dev
      // @ts-ignore
      cfTurnstileToken = typeof turnstile !== 'undefined' ? await new Promise<string>((resolve) => {
        // @ts-ignore
        turnstile.render('#cf-turnstile', {
          sitekey: siteKey,
          callback: (t: string) => resolve(t)
        });
      }) : undefined;
    } catch {}

    const res = await api('/auth/login', { method: 'POST', body: { email, password, cfTurnstileToken } });
    setLoading(false);
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      if (data?.error === 'totp_required') {
        const totp = prompt('Enter your 6-digit TOTP code');
        if (!totp) { setError('TOTP required'); return; }
        setLoading(true);
        const res2 = await api('/auth/login', { method: 'POST', body: { email, password, totp, cfTurnstileToken } });
        setLoading(false);
        if (!res2.ok) { setError('Invalid TOTP'); return; }
        location.href = '/(protected)/dashboard';
        return;
      }
      setError(data?.error || 'Login failed');
      return;
    }
    location.href = '/(protected)/dashboard';
  }

  return (
    <main style={{ padding: 24, fontFamily: 'system-ui' }}>
      <h1>Sign in</h1>
      <form onSubmit={onSubmit} style={{ display: 'grid', gap: 12, maxWidth: 360 }}>
        <input type="email" name="email" placeholder="you@company.com" required />
        <input type="password" name="password" placeholder="Password" required />
        <div id="cf-turnstile" />
        <button type="submit" disabled={loading}>{loading ? 'Signing in…' : 'Sign in'}</button>
        {error && <p style={{ color: 'crimson' }}>{error}</p>}
      </form>
      {/* Turnstile script (no-op if site key not set) */}
      {siteKey && <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" defer></script>}
    </main>
  );
}
