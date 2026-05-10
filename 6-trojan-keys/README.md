# Lab #6 - Trojan Keys

> **TL;DR**: The app uses `node-jose@0.10.0` to verify JWTs. That version ignores the trusted keystore when a `jwk` header parameter is present. Embed your own public key in the token header, sign with the matching private key.

## Vulnerability

`node-jose < 0.11.0` has a flaw in its JWS verification path: if the token header contains a `jwk` field, the library resolves the verification key from that embedded object - bypassing the keystore entirely. The developer's code is correct; the library is the bug.

- **Stack**: Node.js + Express + `node-jose@0.10.0`
- **Class**: JWK header injection

## Quick Start

```bash
docker build -t lab6 .
docker run -p 3000:3000 lab6
```

Without Docker:

```bash
npm install
node index.js
```

Open `http://localhost:3000`. Keys are loaded from `keys/private.pem` and `keys/public.pem`.

## Mission

1. Login as any user (not `admin`) -> get a `session` cookie with an RS256 JWT
2. Note: the server token has no `jwk` field in its header
3. Generate a fresh RSA keypair (your attacker keypair)
4. Forge a JWT with `role: admin` and your public key in the header as `jwk`
5. Sign it with your private key
6. Replace your `session` cookie with the forged token
7. Call `GET /api/admin/tokens` -> capture the flag

## Hints

- The JWKS endpoint (`/.well-known/jwks.json`) shows the JWK format the server uses - model your embedded key on that structure
- The dashboard decodes your current token for inspection
- Only `kty`, `n`, `e` are required in the embedded JWK; `use` and `alg` are optional
- Tools: Burp JWT Editor ("Embedded JWK" attack), `jwt_tool --exploit ki`, or the PoC below

## PoC

```bash
pip install requests cryptography pwntools
python poc.py
# or: python poc.py --url http://localhost:3000
```

## Solution

Full walkthrough: [SOLUTION.md](./SOLUTION.md)

## References

- [JWT attacks - Web Security Academy (PortSwigger)](https://portswigger.net/web-security/jwt) - Explains the jwk header parameter and why trusting attacker-supplied key material is dangerous
- [JWT self-signed JWK header supported - PortSwigger KB](https://portswigger.net/kb/issues/00200902_jwt-self-signed-jwk-header-supported) - Burp scanner issue definition with impact description
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517) - The standard defining the jwk header parameter structure that the attack abuses
