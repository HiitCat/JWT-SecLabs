const express      = require('express');
const cookieParser = require('cookie-parser');
const jwt          = require('jsonwebtoken');
const fs           = require('fs');
const path         = require('path');

const app = express();
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

const KEYS_DIR   = path.join(__dirname, 'keys');
const DEFAULT_KID = 'default';
const DEFAULT_KEY = fs.readFileSync(path.join(KEYS_DIR, DEFAULT_KID + '.key'));

function issueToken(payload) {
  return jwt.sign(payload, DEFAULT_KEY, { algorithm: 'HS256', keyid: DEFAULT_KID });
}

function verifyToken(token) {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded?.header) throw new Error('Malformed token.');

  const kid     = decoded.header.kid || DEFAULT_KID;
  const keyPath = path.join(KEYS_DIR, kid);
  const key     = fs.readFileSync(keyPath);

  return jwt.verify(token, key, { algorithms: ['HS256'] });
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

app.get('/api/admin/alerts', (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Unauthenticated.' });
  try {
    const payload = verifyToken(token);
    if (payload.role !== 'admin') return res.status(403).json({ error: 'Forbidden.' });
    res.json({
      flag: 'FLAG{k1d_p4th_tr4v3rs4l_null_s3cr3t}',
      alerts: [
        { id: 1, severity: 'critical', message: 'Unauthorized access attempt from 10.0.0.42', timestamp: '2024-05-06T14:23:11Z' },
        { id: 2, severity: 'high',     message: 'Brute force detected on /api/login',          timestamp: '2024-05-06T14:19:45Z' },
        { id: 3, severity: 'medium',   message: 'Unusual token activity from user bob',         timestamp: '2024-05-06T13:58:02Z' },
      ],
    });
  } catch {
    res.status(401).json({ error: 'Invalid session.' });
  }
});

app.listen(3000, () => console.log('[Lab 5 - Sentinel] Running on http://localhost:3000'));
