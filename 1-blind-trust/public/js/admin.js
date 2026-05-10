async function init() {
  const meRes = await fetch('/api/me').catch(() => null);
  if (!meRes || !meRes.ok) return (window.location.href = '/');
  const { name, role } = await meRes.json();
  document.getElementById('avatar').textContent    = name[0].toUpperCase();
  document.getElementById('chip-name').textContent = name;
  document.getElementById('chip-role').textContent = role;

  const res = await fetch('/api/admin/users').catch(() => null);
  if (!res || res.status === 401) return (window.location.href = '/');

  if (res.status === 403) {
    document.getElementById('view-denied').classList.remove('hidden');
    return;
  }

  const data = await res.json();
  document.getElementById('view-denied').classList.add('hidden');
  document.getElementById('view-admin').classList.remove('hidden');
  document.getElementById('flag-display').textContent = data.flag;

  const tbody = document.getElementById('user-table');
  for (const u of data.users) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${u.id}</td><td>${u.name}</td><td><span class="role-pill ${u.role}">${u.role}</span></td><td>${u.lastSeen}</td>`;
    tbody.appendChild(tr);
  }
}

document.getElementById('logout-btn').addEventListener('click', () => {
  document.cookie = 'session=; Max-Age=0; path=/';
  window.location.href = '/';
});

init();
