export default async function StatusPage() {
  const api = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8787';
  const res = await fetch(`${api}/health`, { cache: 'no-store' });
  const data = await res.json().catch(() => ({ ok: false }));
  return (
    <main style={{ padding: 24, fontFamily: 'system-ui' }}>
      <h1>Status</h1>
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </main>
  );
}
