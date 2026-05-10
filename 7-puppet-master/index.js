const express      = require('express');
const cookieParser = require('cookie-parser');
const jwt          = require('jsonwebtoken');
const jwksRsa      = require('jwks-rsa');
const { createPublicKey } = require('crypto');
const { readFileSync }   = require('fs');
const path = require('path');

const app = express();
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

const KEY_DIR     = path.join(__dirname, 'keys');
const PRIVATE_PEM = readFileSync(path.join(KEY_DIR, 'private.pem'), 'utf8');
const PUBLIC_PEM  = readFileSync(path.join(KEY_DIR, 'public.pem'),  'utf8');
const SERVER_KID  = 'nexus-key-1';

const serverJwk = (() => {
  const k = createPublicKey(PUBLIC_PEM).export({ format: 'jwk' });
  return { ...k, kid: SERVER_KID, use: 'sig', alg: 'RS256' };
})();

function issueToken(payload) {
  return jwt.sign(payload, PRIVATE_PEM, { algorithm: 'RS256', keyid: SERVER_KID });
}

function verifyToken(token) {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded?.header) throw new Error('Malformed token.');

  const jwksUri = decoded.header.jku || 'http://localhost:3000/.well-known/jwks.json';

  return new Promise((resolve, reject) => {
    const client = jwksRsa({ jwksUri, cache: false, timeout: 5000 });
    jwt.verify(
      token,
      (header, cb) => client.getSigningKey(header.kid, (err, key) => {
        if (err) return cb(err);
        cb(null, key.getPublicKey());
      }),
      { algorithms: ['RS256'] },
      (err, payload) => { if (err) reject(err); else resolve(payload); }
    );
  });
}

app.post('/api/login', (req, res) => {
  const { username } = req.body;
  if (!username?.trim()) return res.status(400).json({ error: 'Username is required.' });
  if (username.toLowerCase() === 'admin') return res.status(400).json({ error: 'This username is not available.' });

  const token = issueToken({ name: username, role: 'developer' });
  res.cookie('session', token, { sameSite: 'strict' });
  res.json({ success: true });
});

app.get('/api/me', async (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Unauthenticated.' });
  try {
    const payload = await verifyToken(token);
    res.json({ name: payload.name, role: payload.role });
  } catch {
    res.status(401).json({ error: 'Invalid session.' });
  }
});

app.get('/api/admin/config', async (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Unauthenticated.' });
  try {
    const payload = await verifyToken(token);
    if (payload.role !== 'admin') return res.status(403).json({ error: 'Forbidden.' });
    res.json({
      flag: 'FLAG{jku_1nj3ct10n_br1ng_y0ur_0wn_k3ys3t}',
      config: {
        environment:  'production',
        keyRotation:  'manual',
        signingAlg:   'RS256',
        tokenTTL:     '3600s',
        allowedScopes: ['read', 'write', 'admin'],
      },
    });
  } catch {
    res.status(401).json({ error: 'Invalid session.' });
  }
});

app.get('/.well-known/jwks.json', (_req, res) => {
  res.json({ keys: [serverJwk] });
});

app.listen(3000, () => console.log('[Lab 7 - Nexus] Running on http://localhost:3000'));
