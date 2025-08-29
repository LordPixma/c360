"use client";

import { useEffect, useState } from 'react';

export default function ClientGuard({ children }: { children: React.ReactNode }) {
  const [ok, setOk] = useState(false);
  useEffect(() => {

    // For development, skip API check if API is not available
    if (process.env.NODE_ENV === 'development') {
      const api = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8787';
      fetch(`${api}/auth/me`, { credentials: 'include' })
        .then(r => r.json())
        .then(d => {
          if (!d?.authenticated) {
            // API available but not authenticated, redirect
            location.href = '/signin';
          } else {
            setOk(true);
          }
        })
        .catch(() => {
          // API not available in development, allow access
          setOk(true);
        });
    } else {
      const api = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8787';
      fetch(`${api}/auth/me`, { credentials: 'include' })
        .then(r => r.json())
        .then(d => {
          if (!d?.authenticated) location.href = '/signin';
          else setOk(true);
        })
        .catch(() => location.href = '/signin');
    }

    // In development, skip auth check if API is not available
    if (process.env.NODE_ENV !== 'production') {
      setOk(true);
      return;
    }
    
    const api = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8787';
    fetch(`${api}/auth/me`, { credentials: 'include' })
      .then(r => r.json())
      .then(d => {
        if (!d?.authenticated) location.href = '/signin';
        else setOk(true);
      })
      .catch(() => {
        // In development, allow access even if API is down
        if (process.env.NODE_ENV !== 'production') {
          setOk(true);
        } else {
          location.href = '/signin';
        }
      });
  }, []);
  if (!ok) return null;
  return <>{children}</>;
}
