import 'server-only';
import { resolveBrand } from '../../lib/branding';

export async function getBranding(tenant?: string) {
  let brand = resolveBrand(tenant);
  if (!tenant) return brand;
  try {
    const api = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8787';
    const res = await fetch(`${api}/branding?tenant=${tenant}`, { next: { revalidate: 60 } });
    if (res.ok) {
      const data = await res.json();
      if (data?.brand) brand = { logoText: data.brand.logo_text, primary: data.brand.primary_color, secondary: data.brand.secondary_color } as any;
    }
  } catch {}
  return brand;
}
