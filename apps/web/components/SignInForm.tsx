"use client";

import { useState, useEffect } from 'react';
import { api } from '../lib/apiClient';
import { M365SignInButton } from './M365SignInButton';

interface SignInFormProps {
  siteKey?: string;
  tenant?: string;
}

export function SignInForm({ siteKey, tenant }: SignInFormProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [m365Available, setM365Available] = useState(false);
  const [checkingM365, setCheckingM365] = useState(true);

  // Check if M365 integration is available for this tenant
  useEffect(() => {
    if (!tenant) {
      setCheckingM365(false);
      return;
    }

    api(`/admin/m365/status?tenant=${encodeURIComponent(tenant)}`, { method: 'GET' })
      .then(async (res) => {
        if (res.ok) {
          const data = await res.json();
          setM365Available(data.configured && data.oauthAvailable);
        }
      })
      .catch(() => {
        // M365 not available or error checking
        setM365Available(false);
      })
      .finally(() => {
        setCheckingM365(false);
      });
  }, [tenant]);

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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%' }}>
      {/* M365 Sign-in Option */}
      {!checkingM365 && m365Available && (
        <>
          <M365SignInButton 
            tenant={tenant}
            onError={setError}
            disabled={loading}
          />
          
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '16px',
            margin: '8px 0'
          }}>
            <div style={{ 
              flex: 1, 
              height: '1px', 
              backgroundColor: '#e5e7eb' 
            }} />
            <span style={{ 
              fontSize: '14px', 
              color: '#6b7280',
              fontWeight: '500'
            }}>
              or continue with email
            </span>
            <div style={{ 
              flex: 1, 
              height: '1px', 
              backgroundColor: '#e5e7eb' 
            }} />
          </div>
        </>
      )}

      {/* Email/Password Form */}
      <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <label style={{ fontSize: '14px', fontWeight: '500', color: '#374151' }}>
            Email Address
          </label>
          <input 
            type="email" 
            name="email" 
            placeholder="you@company.com" 
            required 
            style={{
              padding: '12px 16px',
              border: '1px solid #d1d5db',
              borderRadius: '8px',
              fontSize: '16px',
              backgroundColor: 'white',
              transition: 'border-color 0.2s, box-shadow 0.2s',
            }}
            onFocus={(e) => {
              e.target.style.borderColor = '#3b82f6';
              e.target.style.boxShadow = '0 0 0 3px rgba(59, 130, 246, 0.1)';
            }}
            onBlur={(e) => {
              e.target.style.borderColor = '#d1d5db';
              e.target.style.boxShadow = 'none';
            }}
          />
        </div>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <label style={{ fontSize: '14px', fontWeight: '500', color: '#374151' }}>
            Password
          </label>
          <input 
            type="password" 
            name="password" 
            placeholder="Enter your password" 
            required 
            style={{
              padding: '12px 16px',
              border: '1px solid #d1d5db',
              borderRadius: '8px',
              fontSize: '16px',
              backgroundColor: 'white',
              transition: 'border-color 0.2s, box-shadow 0.2s',
            }}
            onFocus={(e) => {
              e.target.style.borderColor = '#3b82f6';
              e.target.style.boxShadow = '0 0 0 3px rgba(59, 130, 246, 0.1)';
            }}
            onBlur={(e) => {
              e.target.style.borderColor = '#d1d5db';
              e.target.style.boxShadow = 'none';
            }}
          />
        </div>
        
        <div id="cf-turnstile" />
        
        <button 
          type="submit" 
          disabled={loading}
          style={{
            padding: '12px 24px',
            backgroundColor: loading ? '#9ca3af' : '#3b82f6',
            color: 'white',
            border: 'none',
            borderRadius: '8px',
            fontSize: '16px',
            fontWeight: '600',
            cursor: loading ? 'not-allowed' : 'pointer',
            transition: 'background-color 0.2s',
          }}
          onMouseOver={(e) => {
            if (!loading) {
              e.currentTarget.style.backgroundColor = '#2563eb';
            }
          }}
          onMouseOut={(e) => {
            if (!loading) {
              e.currentTarget.style.backgroundColor = '#3b82f6';
            }
          }}
        >
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
        
        {error && (
          <div style={{
            padding: '12px 16px',
            backgroundColor: '#fef2f2',
            border: '1px solid #fecaca',
            borderRadius: '8px',
            color: '#dc2626',
            fontSize: '14px'
          }}>
            {error}
          </div>
        )}
        
        {/* Turnstile script (no-op if site key not set) */}
        {siteKey && <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" defer></script>}
      </form>
    </div>
  );
}