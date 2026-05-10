# Lab #5 - Wrong Turn

> **TL;DR**: The server uses the `kid` header as a raw file path to load the HMAC key. Point `kid` at `/dev/null`, sign with an empty secret.

## Vulnerability

The `kid` (Key ID) header parameter is meant to identify which key to use for verification. When a server builds a file path from it without sanitisation, an attacker can traverse the filesystem and point the key lookup at any file - including empty ones.

The vulnerable lookup in `index.js`:

```javascript
const kid     = decoded.header.kid || DEFAULT_KID;
const keyPath = path.join(KEYS_DIR, kid);
const key     = fs.readFileSync(keyPath);
```

`path.join` resolves `../` sequences normally. A `kid` like `../../../../../../dev/null` walks outside the keys directory and reads `/dev/null`, which returns zero bytes. `jsonwebtoken` then verifies the HS256 signature using an empty Buffer as the secret - and any token signed with `hmac(b'', payload)` passes.

- **Stack**: Node.js + Express + `jsonwebtoken`
- **Class**: kid header path traversal

## Quick Start

```bash
docker build -t lab5 .
docker run -p 3000:3000 lab5
```

Without Docker (Linux/macOS only - requires `/dev/null`):

```bash
npm install
node index.js
```

> Note: the exploit targets `/dev/null` and requires a Linux environment. Run inside Docker on Windows.

## Mission

1. Login as any user -> get a `session` cookie
2. Inspect the JWT: notice it has a `kid` header pointing to a key file
3. Craft a new token with `kid: "../../../../../../dev/null"` and `role: admin`
4. Sign it with an empty HMAC secret (0 bytes)
5. Replace your `session` cookie and call `GET /api/admin/alerts`
6. Capture the flag

## Hints

- `fs.readFileSync('/dev/null')` returns an empty Buffer in Node.js
- `jsonwebtoken` accepts an empty Buffer as a valid HMAC key
- Any number of `../` hops works - use enough to reach the filesystem root

## PoC

```bash
pip install requests pwntools

python poc.py
# or: python poc.py --url http://localhost:3000
```

## Solution

Full walkthrough: [SOLUTION.md](./SOLUTION.md)

## References

- [JWT attacks - Web Security Academy (PortSwigger)](https://portswigger.net/web-security/jwt) - Covers the kid parameter and the risks of using it unsanitized for filesystem key lookups
- [JWT Vulnerabilities - HackTricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens) - Covers kid path traversal, SQL injection via kid, and RCE variants with concrete payloads
- [OWASP WSTG - Testing JSON Web Tokens](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens) - OWASP section on kid-related injection vectors
