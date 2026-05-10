<div align="center">

<img src="https://img.shields.io/badge/JWT-SecLabs-black?style=for-the-badge&logo=jsonwebtokens&logoColor=white" alt="JWT SecLabs">

**A hands-on playground for learning JWT vulnerabilities.**  
Break things. Understand why. Do better.

[![Labs](https://img.shields.io/badge/labs-8-blue?style=flat-square)](.)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)](.)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTORS.md)

</div>

---

## What's this?

No boring slides. No multiple-choice quizzes. Just real exploits on real (broken) code.

Each lab is a self-contained Docker app that teaches one JWT attack vector end-to-end: read the vuln, run the exploit, get the flag.

---

## Labs

| # | Name | Vulnerability | Difficulty |
|---|------|--------------|:----------:|
| 1 | [Blind Trust](./1-blind-trust/) | Unverified JWT Signature | 🟢 Easy |
| 2 | [Voiding The Rules](./2-voiding-the-rules/) | `alg: none` Bypass | 🟢 Easy |
| 3 | [Secrets Under The Rug](./3-secrets-under-the-rug/) | Weak HMAC Secret | 🟡 Medium |
| 4 | [Chameleon Hashes](./4-chameleon-hashes/) | RS256 -> HS256 Confusion | 🟠 Hard |
| 5 | [Wrong Turn](./5-wrong-turn/) | `kid` Header Path Traversal | 🟠 Hard |
| 6 | [Trojan Keys](./6-trojan-keys/) | JWK Header Injection | 🔴 Expert |
| 7 | [Puppet Master](./7-puppet-master/) | JKU Header Injection | 🔴 Expert |
| 8 | [Shadow Key](./8-shadow-key/) | Algorithm Confusion + Public Key Recovery | 🔴 Expert |

---

## Quick Start

```bash
cd <lab-folder>
docker build -t <lab-name> .
docker run -p 3000:3000 <lab-name>
# open http://localhost:3000
```

Each lab's README has specific instructions, hints, and a full solution walkthrough.

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- A browser
- Some curiosity

---

## Learning Path

Work through the labs in order - each one builds on the previous:

1. **[Blind Trust](./1-blind-trust/)** - JWT signatures are never verified; modify any claim you like
2. **[Voiding The Rules](./2-voiding-the-rules/)** - Set `alg` to `none` and strip the signature entirely
3. **[Secrets Under The Rug](./3-secrets-under-the-rug/)** - Crack a weak HMAC secret offline, forge an admin token
4. **[Chameleon Hashes](./4-chameleon-hashes/)** - Confuse an RS256 server into accepting HS256 signed with the public key
5. **[Wrong Turn](./5-wrong-turn/)** - Traverse the filesystem via `kid`, sign with an empty key
6. **[Trojan Keys](./6-trojan-keys/)** - Embed your own public key in the token header, bypass the keystore
7. **[Puppet Master](./7-puppet-master/)** - Point `jku` at your own JWKS server, sign with your own key
8. **[Shadow Key](./8-shadow-key/)** - Recover the hidden RSA public key from two signatures (sig2n), then forge

---

## Contributing

PRs welcome. See [CONTRIBUTORS.md](./CONTRIBUTORS.md) for guidelines.

---

<div align="center">

*"Don't trust what you didn't sign. Don't sign what you didn't validate."*

</div>
