import { headers } from 'next/headers';
import { parseHost, tenantFromHost } from '../../../lib/tenant';
import { resolveBrand } from '../../../lib/branding';
import ClientGuard from './protect';

export default function DashboardPage() {
  const hdrs = headers();
  const hostname = parseHost(hdrs.get('host'));
  const { tenant } = tenantFromHost(hostname);
  const brand = resolveBrand(tenant);

  return (
    <ClientGuard>
      <main style={{ padding: 24, fontFamily: 'system-ui' }}>
        <h1 style={{ color: brand.primary }}>{brand.logoText} – Dashboard</h1>
        <p>Welcome{tenant ? ` to ${tenant}` : ''}. This is your dashboard.</p>
      </main>
    </ClientGuard>
  );
}
