const express      = require('express');
const cookieParser = require('cookie-parser');
const jwt          = require('jsonwebtoken');
const crypto       = require('crypto');

const app = express();
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

const SECRET = crypto.randomBytes(32).toString('hex');

function getSession(req) {
  const token = req.cookies.session;
  if (!token) return null;
  try {
    return jwt.decode(token);
  } catch {
    return null;
  }
}

app.post('/api/login', (req, res) => {
  const { username } = req.body;
  if (!username?.trim()) return res.status(400).json({ error: 'Username is required.' });
  if (username.toLowerCase() === 'admin') return res.status(400).json({ error: 'This username is not available.' });
  const token = jwt.sign({ name: username, role: 'analyst' }, SECRET, { algorithm: 'HS256' });
  res.cookie('session', token, { sameSite: 'strict' });
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  const payload = getSession(req);
  if (!payload) return res.status(401).json({ error: 'Unauthenticated.' });
  res.json({ name: payload.name, role: payload.role });
});

app.get('/api/admin/users', (req, res) => {
  const payload = getSession(req);
  if (!payload) return res.status(401).json({ error: 'Unauthenticated.' });
  if (payload.role !== 'admin') return res.status(403).json({ error: 'Forbidden.' });
  res.json({
    flag: 'FLAG{bl1nd_trust_s1gn4tur3_n3v3r_ch3ck3d}',
    users: [
      { id: 1, name: 'alice',   role: 'analyst', lastSeen: '2026-05-05' },
      { id: 2, name: 'bob',     role: 'analyst', lastSeen: '2026-05-04' },
      { id: 3, name: 'charlie', role: 'analyst', lastSeen: '2026-05-01' },
      { id: 4, name: 'admin',   role: 'admin',   lastSeen: '2026-05-06' },
    ],
  });
});

app.listen(3000, () => console.log('[Lab 1 - Meridian] Running on http://localhost:3000'));
