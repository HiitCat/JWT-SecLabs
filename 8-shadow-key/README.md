# Lab #8 - Shadow Key

> **TL;DR**: The server accepts both RS256 and HS256. The public key is never exposed. Derive it from two RS256 signatures using the sig2n algorithm, then forge an HS256 token signed with the PEM as the HMAC secret.

## Vulnerability

This lab combines two weaknesses:

1. The server accepts both RS256 and HS256 tokens for the same key material - allowing algorithm confusion attacks (same as Lab #4).
2. The RSA public key is not exposed via any API endpoint - so the attacker cannot just read it.

The sig2n technique recovers the RSA modulus from any two RS256 tokens signed by the same private key. Once the public key is known, the HS256 confusion attack from Lab #4 applies.

The server's `verifyToken`:

```javascript
function verifyToken(token) {
  return jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256', 'HS256'] });
}
```

`jsonwebtoken@8.5.1` allows an RSA public key PEM to be used as an HS256 HMAC secret. An attacker who recovers the public key can therefore forge admin tokens.

- **Stack**: Node.js + Express + `jsonwebtoken@8.5.1`
- **Class**: RS256/HS256 algorithm confusion + public key recovery (sig2n)

## Quick Start

```bash
docker build -t lab8 .
docker run -p 3000:3000 lab8
```

Without Docker:

```bash
npm install
node index.js
```

Open `http://localhost:3000`.

## Mission

1. Login as any user twice -> collect two different RS256 tokens
2. Use the sig2n algorithm to derive the RSA public key from the two signatures
3. Forge an HS256 token with `role: admin`, signed using the recovered PEM as the HMAC key
4. Call `GET /api/admin/users`
5. Capture the flag

## Hints

- RS256 is deterministic (PKCS#1 v1.5 padding) - two tokens for the same payload would be identical. The server adds a `jti` claim to each token to ensure they differ.
- sig2n: `sig^e - em(msg)` is a multiple of `n` for every valid RS256 signature. `gcd` of two such values recovers `n` (with high probability).
- The HS256 secret is the raw PEM bytes of the public key - header, base64 body, footer, newlines included.
- The computation involves large integer exponentiation (`sig^65537`). The PoC uses `gmpy2` for speed.

## PoC

```bash
pip install requests gmpy2 pwntools cryptography

python poc.py
# or: python poc.py --url http://localhost:3000
```

The key derivation takes a few seconds with `gmpy2`.

## Solution

Full walkthrough: [SOLUTION.md](./SOLUTION.md)

## References

- [Algorithm confusion attacks - Web Security Academy (PortSwigger)](https://portswigger.net/web-security/jwt/algorithm-confusion) - Covers the no-exposed-key variant and explains how n is derived from two signature pairs using GCD
- [rsa_sign2n - GitHub (silentsignal)](https://github.com/silentsignal/rsa_sign2n) - Original research tool that formalized deriving RSA public keys from message-signature pairs
- [The Ultimate Guide to JWT Vulnerabilities - PentesterLab](https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide) - Covers the sig2n attack in context with the broader RS256/HS256 confusion chain
