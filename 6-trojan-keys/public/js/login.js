const form   = document.getElementById('login-form');
const errBox = document.getElementById('error');
const btn    = document.getElementById('submit-btn');

form.addEventListener('submit', async e => {
  e.preventDefault();
  errBox.classList.add('hidden');
  btn.disabled    = true;
  btn.textContent = 'Signing in...';

  const username = document.getElementById('username').value.trim();

  const res  = await fetch('/api/login', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ username })
  }).catch(() => null);

  btn.disabled    = false;
  btn.textContent = 'Sign in';

  if (!res) return showError('Could not reach the server. Try again.');
  const data = await res.json();
  if (!res.ok) return showError(data.error);

  window.location.href = '/dashboard.html';
});

function showError(msg) {
  errBox.textContent = msg;
  errBox.classList.remove('hidden');
}
