# Lab #4 - Chameleon Hashes

> **TL;DR**: Tokens are issued with RS256, but the server also accepts HS256 using the same key. Fetch the public key, use it as an HMAC secret, forge an admin token.

## Vulnerability

Algorithm confusion attacks exploit servers that verify JWTs without enforcing a strict algorithm. If a server signs with RS256 (asymmetric) but also accepts HS256 (symmetric) on the same key material, an attacker who knows the public key can forge valid tokens — the public key is, by definition, not secret.

- **Stack**: Node.js + Express + `jsonwebtoken@8.5.1`
- **Class**: RS256 -> HS256 algorithm confusion

## Quick Start

```bash
docker build -t lab4 .
docker run -p 3000:3000 lab4
```

Without Docker:

```bash
npm install
node index.js
```

Keys are loaded from `keys/private.pem` and `keys/public.pem`. Open `http://localhost:3000`.

## Mission

1. Login as any user (not `root`) -> get an RS256 `session` cookie
2. Fetch the public key from `GET /.well-known/jwks.json` (fields `n` and `e`)
3. Reconstruct the RSA public key as a PEM string
4. Forge a JWT with `role: admin`, signed with **HS256** using the PEM bytes as the HMAC secret
5. Replace your `session` cookie with the forged token
6. Call `GET /api/admin/keys`
7. Capture the flag

## Hints

- The JWKS endpoint gives you `n` and `e` - enough to reconstruct the full public key
- The server uses the PEM string directly as the HMAC key when verifying HS256
- Tools: Burp JWT Editor, `jwt_tool`, or the Python script below
- `algorithms: ['RS256', 'HS256']` in the verify call is the smoking gun

## PoC

```bash
pip install requests cryptography pwntools
python poc.py
# or: python poc.py --url http://localhost:3000
```

## Solution

Full walkthrough: [SOLUTION.md](./SOLUTION.md)

## References

- [Algorithm confusion attacks - Web Security Academy (PortSwigger)](https://portswigger.net/web-security/jwt/algorithm-confusion) - Full explanation of why treating a public key as an HMAC secret breaks the security model
- [Critical vulnerabilities in JSON Web Token libraries - Auth0](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) - Original disclosure describing the attack across multiple JWT libraries
- [RFC 8725 - JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725) - IETF BCP 225 recommending that servers pin the expected algorithm rather than reading it from the header
