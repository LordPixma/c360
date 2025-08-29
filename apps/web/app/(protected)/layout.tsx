import { headers } from 'next/headers';
import { parseHost, tenantFromHost } from '../../lib/tenant';
import { resolveBrand } from '../../lib/branding';
import { api } from '../../lib/apiClient';
import { LogoutButton } from '../../components/LogoutButton';
import { getBranding } from '../actions/getBranding';

async function isAuthed() {

  // For development, skip API check when API is not available
  if (process.env.NODE_ENV === 'development') {
    try {
      const api = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8787';
      const res = await fetch(`${api}/auth/me`, { cache: 'no-store', credentials: 'include' });
      if (!res.ok) return true; // Default to authenticated for development
      const data = await res.json();
      return Boolean(data?.authenticated);
    } catch (error) {
      // API not available, default to authenticated for development
      return true;
    }
  }
  
  const api = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8787';
  const res = await fetch(`${api}/auth/me`, { cache: 'no-store', credentials: 'include' });
  if (!res.ok) return false;
  const data = await res.json();
  return Boolean(data?.authenticated);
  // In development, skip auth check
  if (process.env.NODE_ENV !== 'production') {
    return true;
  }
  
  try {
    const api = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8787';
    const res = await fetch(`${api}/auth/me`, { cache: 'no-store', credentials: 'include' });
    if (!res.ok) return false;
    const data = await res.json();
    return Boolean(data?.authenticated);
  } catch {
    return process.env.NODE_ENV !== 'production';
  }
}

export default async function ProtectedLayout({ children }: { children: React.ReactNode }) {
  const authed = await isAuthed();
  if (!authed) {
    // Use a client-side redirect fallback
    return (
      <html lang="en"><body><script>location.href='/signin';</script></body></html>
    );
  }
  return (
    <html lang="en">
      <body style={{ margin: 0, padding: 0 }}>
      <body>
        {children}
      </body>
    </html>
  );
}
