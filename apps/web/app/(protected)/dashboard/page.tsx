import { headers } from 'next/headers';
import { parseHost, tenantFromHost } from '../../../lib/tenant';
import { resolveBrand } from '../../../lib/branding';
import ClientGuard from './protect';
import DashboardContent from './DashboardContent';

export default function DashboardPage() {
  const hdrs = headers();
  const hostname = parseHost(hdrs.get('host'));
  const { tenant } = tenantFromHost(hostname);
  const brand = resolveBrand(tenant);

  return (
    <ClientGuard>
      <DashboardContent brand={brand} tenant={tenant} />
    </ClientGuard>
  );
}
