"use client";

import { useEffect, useState } from 'react';

export default function ClientGuard({ children }: { children: React.ReactNode }) {
  const [ok, setOk] = useState(false);
  useEffect(() => {
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
