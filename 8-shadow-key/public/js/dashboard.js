async function initApp() {
  const res = await fetch('/api/me').catch(() => null);
  if (!res || res.status === 401) return (window.location.href = '/');

  const user = await res.json();
  document.getElementById('avatar').textContent    = user.name.slice(0, 2).toUpperCase();
  document.getElementById('chip-name').textContent = user.name;
  document.getElementById('chip-role').textContent = user.role;

  const token = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('session='));
  if (token) {
    document.getElementById('token-display').textContent = token.slice('session='.length);
  }

  document.getElementById('logout-btn').addEventListener('click', () => {
    document.cookie = 'session=; Max-Age=0; path=/';
    window.location.href = '/';
  });

  document.getElementById('copy-jwks-btn').addEventListener('click', async () => {
    const url = `${window.location.origin}/.well-known/jwks.json`;
    try {
      await navigator.clipboard.writeText(url);
      document.getElementById('copy-jwks-btn').textContent = 'Copied';
      setTimeout(() => {
        document.getElementById('copy-jwks-btn').textContent = 'Copy JWKS URL';
      }, 1200);
    } catch {
      window.prompt('Copy this URL', url);
    }
  });
}

initApp();
