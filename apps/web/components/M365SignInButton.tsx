"use client";

import { useState, useEffect } from 'react';
import { api } from '../lib/apiClient';

interface M365SignInButtonProps {
  tenant?: string;
  onError?: (error: string) => void;
  disabled?: boolean;
}

export function M365SignInButton({ tenant, onError, disabled }: M365SignInButtonProps) {
  const [loading, setLoading] = useState(false);

  async function handleM365SignIn() {
    if (!tenant) {
      onError?.('Tenant not specified');
      return;
    }

    setLoading(true);
    
    try {
      // Get authorization URL from API
      const res = await api(`/auth/m365/authorize?tenant=${encodeURIComponent(tenant)}`, {
        method: 'GET'
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data?.error || 'Failed to initiate M365 sign-in');
      }

      const { authorizeUrl, state } = await res.json();
      
      // Store state for validation on return
      sessionStorage.setItem('m365_state', state);
      
      // Redirect to Microsoft 365 authorization
      window.location.href = authorizeUrl;
      
    } catch (error) {
      setLoading(false);
      onError?.(error instanceof Error ? error.message : 'M365 sign-in failed');
    }
  }

  const buttonStyle = {
    width: '100%',
    padding: '12px 16px',
    border: '1px solid #d1d5db',
    borderRadius: '8px',
    backgroundColor: 'white',
    color: '#374151',
    fontSize: '0.875rem',
    fontWeight: '500',
    cursor: disabled || loading ? 'not-allowed' : 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    transition: 'all 0.2s ease-in-out',
    opacity: disabled || loading ? 0.6 : 1,
  };

  const hoverStyle = {
    backgroundColor: '#f9fafb',
    borderColor: '#9ca3af',
  };

  return (
    <button
      type="button"
      onClick={handleM365SignIn}
      disabled={disabled || loading}
      style={buttonStyle}
      onMouseEnter={(e) => {
        if (!disabled && !loading) {
          Object.assign(e.currentTarget.style, hoverStyle);
        }
      }}
      onMouseLeave={(e) => {
        Object.assign(e.currentTarget.style, buttonStyle);
      }}
    >
      {loading ? (
        <>
          <div style={{
            width: '16px',
            height: '16px',
            border: '2px solid #d1d5db',
            borderTop: '2px solid #6b7280',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
          }} />
          <span>Connecting...</span>
        </>
      ) : (
        <>
          {/* Microsoft logo */}
          <svg width="16" height="16" viewBox="0 0 23 23" fill="none">
            <rect x="1" y="1" width="10" height="10" fill="#F25022"/>
            <rect x="12" y="1" width="10" height="10" fill="#7FBA00"/>
            <rect x="1" y="12" width="10" height="10" fill="#00A4EF"/>
            <rect x="12" y="12" width="10" height="10" fill="#FFB900"/>
          </svg>
          <span>Continue with Microsoft 365</span>
        </>
      )}
      
      <style dangerouslySetInnerHTML={{
        __html: `
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `
      }} />
    </button>
  );
}

// Callback handler component for M365 OAuth flow
export function M365CallbackHandler() {
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Only run in browser environment
    if (typeof window === 'undefined') return;

    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const storedState = sessionStorage.getItem('m365_state');

    if (!code || !state || state !== storedState) {
      setStatus('error');
      setError('Invalid OAuth callback parameters');
      return;
    }

    // Clear stored state
    sessionStorage.removeItem('m365_state');

    // Exchange code for session
    api('/auth/m365/callback', {
      method: 'POST',
      body: { code, state }
    })
    .then(async (res) => {
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data?.error || 'Authentication failed');
      }
      
      setStatus('success');
      // Redirect to dashboard after successful authentication
      setTimeout(() => {
        window.location.href = '/dashboard';
      }, 1500);
    })
    .catch((error) => {
      setStatus('error');
      setError(error.message);
    });
  }, []);

  if (status === 'processing') {
    return (
      <div style={{ textAlign: 'center', padding: '40px' }}>
        <div style={{
          width: '32px',
          height: '32px',
          border: '3px solid #e5e7eb',
          borderTop: '3px solid #3b82f6',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite',
          margin: '0 auto 16px'
        }} />
        <p>Completing Microsoft 365 sign-in...</p>
      </div>
    );
  }

  if (status === 'success') {
    return (
      <div style={{ textAlign: 'center', padding: '40px' }}>
        <div style={{ fontSize: '48px', marginBottom: '16px' }}>✅</div>
        <p>Successfully signed in! Redirecting...</p>
      </div>
    );
  }

  return (
    <div style={{ textAlign: 'center', padding: '40px' }}>
      <div style={{ fontSize: '48px', marginBottom: '16px' }}>❌</div>
      <p style={{ color: '#dc2626', marginBottom: '16px' }}>Sign-in failed: {error}</p>
      <a href="/signin" style={{ color: '#3b82f6', textDecoration: 'none' }}>
        Return to sign-in
      </a>
    </div>
  );
}