# Lab #7 - Puppet Master

> **TL;DR**: The server fetches the JWKS from the URL in the token's `jku` header without validating the domain. Point `jku` at your own server, sign with your own key.

## Vulnerability

The `jku` (JWK Set URL) header parameter tells a verifier where to fetch the public keys. When a server resolves that URL without checking it against a trusted allowlist, an attacker can point `jku` at any host - including one they control - and forge tokens verified against their own keys.

The developer code uses `jwks-rsa` correctly, but passes `header.jku` directly as the `jwksUri`:

```javascript
const jwksUri = decoded.header.jku || 'http://localhost:3000/.well-known/jwks.json';
const client  = jwksRsa({ jwksUri, cache: false });
```

The library does its job - the bug is in trusting the token's own claim about where to find the keys.

- **Stack**: Node.js + Express + `jsonwebtoken` + `jwks-rsa`
- **Class**: JKU header injection

## Quick Start

```bash
docker build -t lab7 .
docker run -p 3000:3000 lab7
```

Without Docker:

```bash
npm install
node index.js
```

Open `http://localhost:3000`. Keys are loaded from `keys/private.pem` and `keys/public.pem`.

## Mission

1. Login as any user -> get a `session` cookie
2. Generate a fresh RSA keypair (your attacker keypair)
3. Serve your public key as a JWKS on a URL you control (e.g. `http://localhost:3001/jwks.json`)
4. Forge a JWT with `role: admin`, `jku` pointing to your JWKS server, and `kid` matching your key
5. Sign it with your private key
6. Replace your `session` cookie and call `GET /api/admin/config`
7. Capture the flag

## Hints

- You need to host a small HTTP server that returns your JWK Set - the PoC does this automatically
- Both `jku` (the URL) and `kid` (the key ID) must match: `jku` tells the server where to look, `kid` tells it which key to use
- The server's own JWKS is at `/.well-known/jwks.json` - inspect it to understand the expected format

## PoC

```bash
pip install requests cryptography pwntools

# without Docker (node index.js)
python poc.py

# with Docker - the container cannot reach localhost on the host
python poc.py --jwks-host host.docker.internal
```

## Solution

Full walkthrough: [SOLUTION.md](./SOLUTION.md)

## References

- [JWT attacks - Web Security Academy (PortSwigger)](https://portswigger.net/web-security/jwt) - Explains the jku parameter and the server-side fetch that attackers can redirect
- [JWT arbitrary jku header supported - PortSwigger KB](https://portswigger.net/kb/issues/00200904_jwt-arbitrary-jku-header-supported) - Burp scanner issue definition, covering open redirect chaining and lack of domain whitelisting
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517) - Defines the JWKS format the jku URL must return; needed to understand what a malicious endpoint must serve
