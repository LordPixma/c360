"use client";

import { useEffect, useState } from 'react';

export default function ClientGuard({ children }: { children: React.ReactNode }) {
  const [ok, setOk] = useState(false);
  useEffect(() => {
    const api = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8787';
    fetch(`${api}/auth/me`, { credentials: 'include' })
      .then(r => r.json())
      .then(d => {
        if (!d?.authenticated) location.href = '/signin';
        else setOk(true);
      })
      .catch(() => location.href = '/signin');
  }, []);
  if (!ok) return null;
  return <>{children}</>;
}
