async function initApp() {
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

  const adminRes = await fetch('/api/admin/data').catch(() => null);

  if (!adminRes || adminRes.status === 403 || adminRes.status === 401) {
    document.getElementById('view-denied').classList.remove('hidden');
    return;
  }

  const data = await adminRes.json();
  document.getElementById('view-denied').classList.add('hidden');
  document.getElementById('view-admin').classList.remove('hidden');
  document.getElementById('flag-display').textContent = data.flag;

  const tbody = document.getElementById('employee-table');
  data.employees.forEach(emp => {
    const statusClass = emp.status === 'Active' ? 'active' : 'on-leave';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${emp.id}</td>
      <td>${emp.name}</td>
      <td>${emp.dept}</td>
      <td>${emp.salary}</td>
      <td><span class="status-pill ${statusClass}">${emp.status}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

initApp();
