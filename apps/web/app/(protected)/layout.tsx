import { headers } from 'next/headers';
import { parseHost, tenantFromHost } from '../../lib/tenant';
import { resolveBrand } from '../../lib/branding';
import { api } from '../../lib/apiClient';
import { LogoutButton } from '../../components/LogoutButton';
import { getBranding } from '../actions/getBranding';

async function isAuthed() {
  const api = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8787';
  const res = await fetch(`${api}/auth/me`, { cache: 'no-store', credentials: 'include' });
  if (!res.ok) return false;
  const data = await res.json();
  return Boolean(data?.authenticated);
}

export default async function ProtectedLayout({ children }: { children: React.ReactNode }) {
  const authed = await isAuthed();
  const hdrs = headers();
  const hostname = parseHost(hdrs.get('host'));
  const { tenant } = tenantFromHost(hostname);
  const brand = await getBranding(tenant);
  if (!authed) {
    // Use a client-side redirect fallback
    return (
      <html lang="en"><body><script>location.href='/signin';</script></body></html>
    );
  }
  return (
    <html lang="en">
      <body>
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', background: brand.secondary }}>
          <div style={{ color: brand.primary, fontWeight: 700 }}>{brand.logoText}</div>
          <LogoutButton />
        </header>
        {children}
      </body>
    </html>
  );
}
