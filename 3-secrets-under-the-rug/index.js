const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

const SECRET = 'secret';

app.post('/api/login', (req, res) => {
  const { username } = req.body;
  if (!username?.trim()) return res.status(400).json({ error: 'Username is required.' });
  if (username.toLowerCase() === 'admin') return res.status(400).json({ error: 'This username is not available.' });

  const token = jwt.sign({ name: username, role: 'user' }, SECRET);
  res.cookie('session', token, { sameSite: 'strict' });
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Unauthenticated.' });
  try {
    const { name, role } = jwt.verify(token, SECRET);
    res.json({ name, role });
  } catch {
    res.status(401).json({ error: 'Invalid session.' });
  }
});

app.get('/api/admin/users', (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Unauthenticated.' });
  try {
    const payload = jwt.verify(token, SECRET);
    if (payload.role !== 'admin') return res.status(403).json({ error: 'Forbidden.' });
    res.json({
      flag: 'FLAG{w34k_53cr3t5_4r3_n0_s3cr3t5}',
      users: [
        { id: 1, name: 'Alice Martin',   email: 'alice@vaultbox.io',   role: 'admin', storage: '4.2 GB' },
        { id: 2, name: 'Bob Leclerc',    email: 'bob@vaultbox.io',     role: 'user',  storage: '1.1 GB' },
        { id: 3, name: 'Charlie Dupont', email: 'charlie@vaultbox.io', role: 'user',  storage: '800 MB' },
      ]
    });
  } catch {
    res.status(401).json({ error: 'Invalid session.' });
  }
});

app.listen(3000, () => console.log('[Lab 3 - VaultBox] Running on http://localhost:3000'));
