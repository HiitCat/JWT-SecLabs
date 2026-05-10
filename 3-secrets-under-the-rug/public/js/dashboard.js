// Shared: load user identity and wire logout
async function initApp() {
  const res = await fetch('/api/me').catch(() => null);
  if (!res || res.status === 401) return (window.location.href = '/');

  const user = await res.json();

  const initials = user.name.slice(0, 2).toUpperCase();
  document.getElementById('avatar').textContent    = initials;
  document.getElementById('chip-name').textContent = user.name;
  document.getElementById('chip-role').textContent = user.role;

  document.getElementById('logout-btn').addEventListener('click', () => {
    document.cookie = 'session=; Max-Age=0; path=/';
    window.location.href = '/';
  });
}

initApp();
