# Lab #2 - Voiding The Rules

> **TL;DR**: The app verifies JWTs with Authlib 1.6.6, which accepts `alg: none`. Forge an unsigned admin token and bypass authentication entirely.

## Vulnerability

The `alg: none` attack exploits libraries that trust the algorithm declared in the JWT header without enforcing a strict allowlist. A token with `alg: none` carries no signature — anyone can write any payload.

- **Stack**: Python + Flask + Authlib 1.6.6
- **Class**: alg:none bypass

## Quick Start

```bash
docker build -t lab2 .
docker run -p 3000:3000 lab2
```

Without Docker:

```bash
python -m venv .venv && . .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
python app.py
```

Open `http://localhost:3000`.

## Mission

1. Login as any user (not `admin`) to observe the token format
2. Forge a JWT with `alg: none` and `role: admin` in the payload
3. Leave the signature empty (trailing dot: `header.payload.`)
4. Replace your `session` cookie with the forged token
5. Call `GET /api/admin/data`
6. Capture the flag

## Hints

- JWT parts are Base64URL-encoded — you only need `base64` and a text editor
- The trailing dot is required: `header.payload.` — no signature, but the dot must be there
- No login needed; the server never checks if the token was issued by itself

## PoC

```bash
pip install requests pwntools
python poc.py
# or: python poc.py --url http://localhost:3000
```

## Solution

Full walkthrough: [SOLUTION.md](./SOLUTION.md)

## References

- [Critical vulnerabilities in JSON Web Token libraries - Auth0](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) - The original 2015 disclosure naming the alg:none attack and why mixed-case variants (e.g. "NoNe") bypass naive checks
- [JWT none algorithm supported - PortSwigger KB](https://portswigger.net/kb/issues/00200901_jwt-none-algorithm-supported) - Concise definition of the issue and detection guidance
- [CVE-2022-23540 - NVD](https://nvd.nist.gov/vuln/detail/cve-2022-23540) - jsonwebtoken <=8.5.1 accepting alg:none when a falsy secret is passed to jwt.verify()
