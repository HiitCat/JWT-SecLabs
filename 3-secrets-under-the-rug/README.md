# Lab #3 - Secrets Under The Rug

> **TL;DR**: The app signs JWTs with a weak HMAC secret. Crack it offline. Forge an admin token. Win.

## Vulnerability

HMAC-based JWT signing (HS256) is only as strong as its secret. If the secret is weak — say, `password`, `secret`, or `123456` — an attacker with any valid token can brute-force it **offline** in seconds, then forge arbitrary payloads.

No network noise. No account lockouts. Just a wordlist and a CPU.

- **Stack**: Node.js + Express + jsonwebtoken
- **Class**: weak credential / offline brute-force

## Quick Start

```bash
docker build -t lab3 .
docker run -p 3000:3000 lab3
```

Without Docker:

```bash
npm install
node index.js
```

Open `http://localhost:3000`.

## Mission

1. Login as any user (not `admin`) -> get a `session` cookie containing a JWT
2. Crack the HMAC secret offline
3. Forge a new JWT with `{ "name": "hacker", "role": "admin" }`
4. Replace your `session` cookie with the forged token
5. Call `GET /api/admin/users`
6. Capture the flag

## Hints

- The secret is embarrassingly weak
- Hashcat mode for HS256 JWTs: `-m 16500`
- Or just read the source - it's a lab

## PoC

```bash
pip install requests pwntools
python poc.py
# or: python poc.py --url http://localhost:3000
```

## Solution

Full walkthrough: [SOLUTION.md](./SOLUTION.md)

## References

- [Brute Forcing HS256 is Possible - Auth0](https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/) - Why HS256 is symmetric, why short secrets are brute-forceable, and what key size RFC 7518 mandates
- [JWT weak HMAC secret - PortSwigger KB](https://portswigger.net/kb/issues/00200903_jwt-weak-hmac-secret) - Detection and severity definition for weak signing keys
- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) - The base spec; section 8 covers key size requirements for HMAC-based algorithms
