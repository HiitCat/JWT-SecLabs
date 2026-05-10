async function init() {
  const res = await fetch('/api/me').catch(() => null);
  if (!res || !res.ok) return (window.location.href = '/');
  const { name, role } = await res.json();
  document.getElementById('avatar').textContent    = name[0].toUpperCase();
  document.getElementById('chip-name').textContent = name;
  document.getElementById('chip-role').textContent = role;
  document.getElementById('welcome-line').textContent = `Signed in as ${name} - role: ${role}`;
}

document.getElementById('logout-btn').addEventListener('click', () => {
  document.cookie = 'session=; Max-Age=0; path=/';
  window.location.href = '/';
});

init();
