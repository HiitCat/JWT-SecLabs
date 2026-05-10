# Lab #1 - Blind Trust

> **TL;DR**: The server decodes JWTs without verifying signatures. Flip your role to `admin` in the payload - any signature will be accepted.

## Vulnerability

JWT libraries expose two different functions: one to verify a token (checks the signature and claims) and one to merely decode it (base64-decodes the payload, no checks at all). Using the wrong function for authentication is a surprisingly common developer mistake.

Here the server reads the session cookie with `jwt.decode()` on every request. The signature is never validated, so any payload you craft will be accepted as legitimate - including one that promotes you to admin.

- **Stack**: Node.js + Express + `jsonwebtoken` (latest)
- **Class**: Unverified JWT signature

## Quick Start

```bash
docker build -t lab1 .
docker run -p 3000:3000 lab1
```

Without Docker:

```bash
npm install
node index.js
```

Open `http://localhost:3000`. Login with any username (not `admin`).

## Mission

1. Login as any user (not `admin`) -> get a `session` cookie
2. Decode the JWT payload (base64url, the middle part)
3. Change `role` to `admin`
4. Re-encode and replace your cookie (keep the original signature - it will not be checked)
5. Call `GET /api/admin/users`
6. Capture the flag

## Hints

- A JWT is three base64url-encoded parts separated by dots: `header.payload.signature`
- The payload is the middle part - decode it, edit it, re-encode it
- The signature can be anything - even the original one

## PoC

```bash
pip install requests pwntools
python poc.py
# or: python poc.py --url http://localhost:3000
```

## Solution

Full walkthrough: [SOLUTION.md](./SOLUTION.md)

## References

- [JWT attacks - Web Security Academy (PortSwigger)](https://portswigger.net/web-security/jwt) - Core theory on JWT signature verification and what happens when it is skipped
- [JWT signature not verified - PortSwigger KB](https://portswigger.net/kb/issues/00200900_jwt-signature-not-verified) - Burp scanner issue definition explaining root cause and impact
- [OWASP WSTG - Testing JSON Web Tokens](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens) - OWASP testing guide covering all JWT verification failure scenarios
