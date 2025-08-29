type Brand = { logoText: string; primary: string; secondary: string };

const DEFAULT_BRAND: Brand = { logoText: 'Comp360Flow', primary: '#0b62d6', secondary: '#eef6ff' };

const BRAND_MAP: Record<string, Brand> = {
  acme: { logoText: 'ACME Compliance', primary: '#0b8f62', secondary: '#e6fbf1' },
  beta: { logoText: 'Beta Corp Compliance', primary: '#8f0bd6', secondary: '#f5e6fb' }
};

export function resolveBrand(tenant?: string): Brand {
  if (!tenant) return DEFAULT_BRAND;
  return BRAND_MAP[tenant] ?? DEFAULT_BRAND;
}
