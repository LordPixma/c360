// Quick local verification for /auth/login and /whoami
(async () => {
  const base = process.env.API_BASE || 'http://127.0.0.1:8787';
  try {
    const loginRes = await fetch(base + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'dev@example.com', password: 'password1234' })
    });
    const loginText = await loginRes.text();
    console.log('LOGIN STATUS', loginRes.status);
    console.log('LOGIN BODY', loginText);
    if (!loginRes.ok) process.exit(1);
  const login = JSON.parse(loginText);
  const token = login.token;
  if (!token) throw new Error('No token in login response');

    const whoRes = await fetch(base + '/whoami', {
  headers: { Authorization: 'Bearer ' + token }
    });
    const whoText = await whoRes.text();
    console.log('WHOAMI STATUS', whoRes.status);
    console.log('WHOAMI BODY', whoText);
    process.exit(whoRes.ok ? 0 : 1);
  } catch (e) {
    console.error('ERR', e.message);
    process.exit(1);
  }
})();
