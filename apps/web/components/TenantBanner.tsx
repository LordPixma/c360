export function TenantBanner({ tenant }: { tenant?: string }) {
  if (!tenant) return null;
  return (
    <div style={{ background: '#eef6ff', color: '#0b62d6', padding: 8, fontSize: 12 }}>
      Tenant: <strong>{tenant}</strong>
    </div>
  );
}
