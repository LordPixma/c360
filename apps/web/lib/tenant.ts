export function parseHost(hostHeader: string | null | undefined) {
  const host = (hostHeader || '').toLowerCase();
  // Strip port if present
  const [hostname] = host.split(':');
  return hostname;
}

export function tenantFromHost(hostname: string) {
  // dev: foo.localhost or localhost
  if (!hostname) return { tenant: undefined, base: undefined, isCustomDomain: false };
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    const parts = hostname.split('.');
    // localhost or sub.localhost
    if (parts.length >= 3) {
      const tenant = parts.slice(0, parts.length - 2).join('-');
      return { tenant, base: 'localhost', isCustomDomain: false };
    }
    return { tenant: undefined, base: 'localhost', isCustomDomain: false };
  }
  // prod: *.comp360flow.com
  if (hostname === 'comp360flow.com') {
    return { tenant: undefined, base: 'comp360flow.com', isCustomDomain: false };
  }
  if (hostname.endsWith('.comp360flow.com')) {
    const withoutBase = hostname.replace('.comp360flow.com', '');
    return { tenant: withoutBase, base: 'comp360flow.com', isCustomDomain: false };
  }
  // custom domain
  return { tenant: undefined, base: hostname, isCustomDomain: true };
}
