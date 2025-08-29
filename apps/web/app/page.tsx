// runtime defaults for dev; edge runtime can be re-enabled before Pages deploy if needed
import { headers } from 'next/headers';
import { parseHost, tenantFromHost } from '../lib/tenant';
import { TenantBanner } from '../components/TenantBanner';

export default function Home() {
  const hdrs = headers();
  const hostname = parseHost(hdrs.get('host'));
  const info = tenantFromHost(hostname);
  const tenant = info.tenant;

  return (
    <main style={{ padding: 24, fontFamily: 'system-ui' }}>
      <TenantBanner tenant={tenant} />
      <h1>Comp360Flow</h1>
      {tenant ? (
        <p>Welcome to the {tenant} tenant portal.</p>
      ) : (
        <p>Welcome. Sign in to access your tenant or create a new one.</p>
      )}
      <div style={{ marginTop: 16, display: 'flex', gap: 12 }}>
        <a href="/signin">Sign in</a>
        <a href="/signup">Create account</a>
      </div>
    </main>
  );
}
