const express      = require('express');
const cookieParser = require('cookie-parser');
const jose         = require('node-jose');
const { readFileSync } = require('fs');
const path = require('path');

const app = express();
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

const KEY_DIR    = path.join(__dirname, 'keys');
const PUBLIC_PEM  = readFileSync(path.join(KEY_DIR, 'public.pem'),  'utf8');
const PRIVATE_PEM = readFileSync(path.join(KEY_DIR, 'private.pem'), 'utf8');

let keystore;
let signingKey;
const ready = (async () => {
  keystore = jose.JWK.createKeyStore();
  await keystore.add(PUBLIC_PEM,  'pem');
  signingKey = await jose.JWK.asKey(PRIVATE_PEM, 'pem');
})();

async function issueToken(payload) {
  await ready;
  return jose.JWS.createSign(
    { format: 'compact', fields: { typ: 'JWT' } },
    { key: signingKey, reference: false }
  )
  .update(JSON.stringify(payload))
  .final();
}

async function verifyToken(token) {
  await ready;
  const result = await jose.JWS.createVerify(keystore).verify(token);
  return JSON.parse(result.payload);
}

app.post('/api/login', async (req, res) => {
  const { username } = req.body;
  if (!username?.trim()) return res.status(400).json({ error: 'Username is required.' });
  if (username.toLowerCase() === 'admin') return res.status(400).json({ error: 'This username is not available.' });

  const token = await issueToken({ name: username, role: 'developer' });
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

app.get('/api/admin/tokens', async (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Unauthenticated.' });
  try {
    const payload = await verifyToken(token);
    if (payload.role !== 'admin') return res.status(403).json({ error: 'Forbidden.' });
    res.json({
      flag: 'FLAG{jwk_1nj3ct10n_y0ur_k3y_y0ur_rul35}',
      tokens: [
        { id: 'tok-001', issuer: 'PaymentGW',   alg: 'RS256', status: 'active',  issued: '2026-04-01' },
        { id: 'tok-002', issuer: 'NotifySvc',   alg: 'RS256', status: 'active',  issued: '2026-04-15' },
        { id: 'tok-003', issuer: 'AuditLogger', alg: 'RS256', status: 'revoked', issued: '2026-03-20' },
      ],
    });
  } catch {
    res.status(401).json({ error: 'Invalid session.' });
  }
});

app.get('/.well-known/jwks.json', async (_req, res) => {
  await ready;
  res.json({ keys: keystore.toJSON().keys });
});

app.listen(3000, () => console.log('[Lab 6 - KeyForge] Running on http://localhost:3000'));
