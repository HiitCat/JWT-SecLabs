// Shared: load user identity and wire logout
async function initApp() {
  const res = await fetch('/api/me').catch(() => null);
  if (!res || res.status === 401) return (window.location.href = '/');

  const user = await res.json();

  const initials = user.name.slice(0, 2).toUpperCase();
  document.getElementById('avatar').textContent    = initials;
  document.getElementById('chip-name').textContent = user.name;
  document.getElementById('chip-role').textContent = user.role;
  document.getElementById('welcome-line').textContent = `${user.name} (${user.role}) is connected to CertFlow.`;

  document.getElementById('logout-btn').addEventListener('click', () => {
    document.cookie = 'session=; Max-Age=0; path=/';
    window.location.href = '/';
  });

  document.getElementById('copy-cert-url').addEventListener('click', async () => {
    const certUrl = `${window.location.origin}/.well-known/jwks.json`;
    try {
      await navigator.clipboard.writeText(certUrl);
      document.getElementById('copy-cert-url').textContent = 'Copied';
      setTimeout(() => {
        document.getElementById('copy-cert-url').textContent = 'Copy JWKS URL';
      }, 1200);
    } catch {
      window.prompt('Copy this URL', certUrl);
    }
  });
}

initApp();
