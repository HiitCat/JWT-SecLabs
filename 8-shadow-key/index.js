const express      = require('express');
const cookieParser = require('cookie-parser');
const jwt          = require('jsonwebtoken');
const fs           = require('fs');
const path         = require('path');
const { randomUUID } = require('crypto');

const app = express();
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

const KEY_DIR     = path.join(__dirname, 'keys');
const PRIVATE_KEY = fs.readFileSync(path.join(KEY_DIR, 'private.pem'), 'utf8');
const PUBLIC_KEY  = fs.readFileSync(path.join(KEY_DIR, 'public.pem'),  'utf8');

function issueToken(payload) {
  return jwt.sign({ ...payload, jti: randomUUID() }, PRIVATE_KEY, { algorithm: 'RS256' });
}

function verifyToken(token) {
  return jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256', 'HS256'] });
}

app.post('/api/login', (req, res) => {
  const { username } = req.body;
  if (!username?.trim()) return res.status(400).json({ error: 'Username is required.' });
  if (username.toLowerCase() === 'admin') return res.status(400).json({ error: 'This username is not available.' });

  const token = issueToken({ name: username, role: 'analyst' });
  res.cookie('session', token, { sameSite: 'strict' });
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Unauthenticated.' });
  try {
    const payload = verifyToken(token);
    res.json({ name: payload.name, role: payload.role });
  } catch {
    res.status(401).json({ error: 'Invalid session.' });
  }
});

app.get('/api/admin/users', (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Unauthenticated.' });
  try {
    const payload = verifyToken(token);
    if (payload.role !== 'admin') return res.status(403).json({ error: 'Forbidden.' });
    res.json({
      flag: 'FLAG{sh4d0w_k3y_s1gn4tur3_l34ks_pub_k3y}',
      users: [
        { id: 1, username: 'alice',  role: 'analyst', lastLogin: '2024-05-06T14:10:00Z' },
        { id: 2, username: 'bob',    role: 'analyst', lastLogin: '2024-05-06T13:40:00Z' },
        { id: 3, username: 'admin',  role: 'admin',   lastLogin: '2024-05-06T09:00:00Z' },
      ],
    });
  } catch {
    res.status(401).json({ error: 'Invalid session.' });
  }
});

app.listen(3000, () => console.log('[Lab 8 - Atlas] Running on http://localhost:3000'));
