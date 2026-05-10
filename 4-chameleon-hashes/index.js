const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { createPublicKey } = require('crypto');
const { readFileSync } = require('fs');
const path = require('path');

const app = express();
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

const KEY_DIR = path.join(__dirname, 'keys');
let PUBLIC_KEY;
let PRIVATE_KEY;

try {
  PUBLIC_KEY = readFileSync(path.join(KEY_DIR, 'public.pem'), 'utf8');
  PRIVATE_KEY = readFileSync(path.join(KEY_DIR, 'private.pem'), 'utf8');
} catch (error) {
  console.error('Failed to load key files from ./keys/public.pem and ./keys/private.pem');
  throw error;
}

const KEY_ID = 'k-' + Math.floor(Math.random() * 1e6).toString(16).padStart(6, '0');
const PUBLIC_JWK = createPublicKey(PUBLIC_KEY).export({ format: 'jwk' });

app.post('/api/login', (req, res) => {
  const { username } = req.body;
  if (!username?.trim()) return res.status(400).json({ error: 'Username is required.' });
  if (username.toLowerCase() === 'root') return res.status(400).json({ error: 'This username is not available.' });

  const token = jwt.sign({ name: username, role: 'analyst' }, PRIVATE_KEY, {
    algorithm: 'RS256',
    keyid: KEY_ID,
  });
  res.cookie('session', token, { sameSite: 'strict' });
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Unauthenticated.' });

  try {
    const payload = jwt.verify(token, PUBLIC_KEY, {
      algorithms: ['RS256', 'HS256'],
      allowInvalidAsymmetricKeyTypes: true,
    });
    res.json({ name: payload.name, role: payload.role });
  } catch {
    res.status(401).json({ error: 'Invalid session.' });
  }
});

app.get('/api/admin/keys', (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Unauthenticated.' });

  try {
    const payload = jwt.verify(token, PUBLIC_KEY, {
      algorithms: ['RS256', 'HS256'],
      allowInvalidAsymmetricKeyTypes: true,
    });

    if (payload.role !== 'admin') return res.status(403).json({ error: 'Forbidden.' });

    res.json({
      flag: 'FLAG{r54_publ1c_k3y5_4r3_n0t_hm4c_s3cr3t5}',
      keys: [
        { id: 'k-1024', owner: 'Payroll API', scope: 'write:salary', lastRotation: '2026-04-11' },
        { id: 'k-2048', owner: 'Tax Gateway', scope: 'write:exports', lastRotation: '2026-04-28' },
        { id: 'k-4096', owner: 'Internal Ledger', scope: 'admin:all', lastRotation: '2026-05-01' },
      ],
    });
  } catch {
    res.status(401).json({ error: 'Invalid session.' });
  }
});

app.get('/.well-known/jwks.json', (_req, res) => {
  res.json({
    keys: [
      {
        kty: PUBLIC_JWK.kty,
        kid: KEY_ID,
        n: PUBLIC_JWK.n,
        e: PUBLIC_JWK.e,
      },
    ],
  });
});

app.listen(3000, () => {
  console.log('[Lab 4 - CertFlow] Running on http://localhost:3000');
});
