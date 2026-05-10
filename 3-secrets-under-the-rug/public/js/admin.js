async function initApp() {
  // Load current user for the sidebar
  const meRes = await fetch('/api/me').catch(() => null);
  if (!meRes || meRes.status === 401) return (window.location.href = '/');

  const user = await meRes.json();
  document.getElementById('avatar').textContent    = user.name.slice(0, 2).toUpperCase();
  document.getElementById('chip-name').textContent = user.name;
  document.getElementById('chip-role').textContent = user.role;

  document.getElementById('logout-btn').addEventListener('click', () => {
    document.cookie = 'session=; Max-Age=0; path=/';
    window.location.href = '/';
  });

  // Try to load admin data
  const adminRes = await fetch('/api/admin/users').catch(() => null);

  if (!adminRes || adminRes.status === 403 || adminRes.status === 401) {
    document.getElementById('view-denied').classList.remove('hidden');
    return;
  }

  const data = await adminRes.json();
  document.getElementById('view-denied').classList.add('hidden');
  document.getElementById('view-admin').classList.remove('hidden');
  document.getElementById('flag-display').textContent = data.flag;

  const tbody = document.getElementById('user-table');
  data.users.forEach(u => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${u.id}</td>
      <td>${u.name}</td>
      <td>${u.email}</td>
      <td><span class="badge-role ${u.role}">${u.role}</span></td>
      <td>${u.storage}</td>
    `;
    tbody.appendChild(tr);
  });
}

initApp();
