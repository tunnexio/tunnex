#!/usr/bin/env python3
"""Exercise the actual Compose edge startup script without starting a server."""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


class EdgeIPTLS(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tunnex-edge-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'Caddyfile'
        self.args = self.root / 'args'
        stub = self.root / 'caddy'
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_CADDY_ARGS"\n')
        stub.chmod(0o755)
        compose = Path(__file__).with_name('tunnex.yml').read_text()
        service = compose.split('\n  caddy:\n', 1)[1].split('\n  node-agent:\n', 1)[0]
        self.script = textwrap.dedent(service.split('    command:\n      - |\n', 1)[1].split('    ports:', 1)[0]).replace('$$', '$').replace('/tmp/tunnex-Caddyfile', str(self.config))

    def run_edge(self, origin, ip=''):
        return subprocess.run(['sh', '-ec', self.script], env={**os.environ,
            'PATH': str(self.root) + os.pathsep + os.environ['PATH'],
            'TEST_CADDY_ARGS': str(self.args),
            'TUNNEX_EDGE_LISTEN': origin, 'TUNNEX_EDGE_PUBLIC_IP': ip},
            capture_output=True, text=True)

    def test_existing_http_and_dns_modes(self):
        for origin in ['http://:80', 'https://vpn.example.com']:
            with self.subTest(origin=origin):
                self.assertEqual(self.run_edge(origin).returncode, 0)
                self.assertEqual(self.args.read_text().splitlines(),
                    ['reverse-proxy', '--from', origin, '--to', 'nginx:8080'])
                self.assertFalse(self.config.exists())

    def test_ip_uses_public_acme_and_ip_sni(self):
        for origin in ['https://51.20.98.153', 'https://51.20.98.153:443']:
            with self.subTest(origin=origin):
                result = self.run_edge(origin, '51.20.98.153')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.args.read_text().splitlines(),
                    ['run', '--config', str(self.config), '--adapter', 'caddyfile'])
                config = self.config.read_text()
                for expected in ['default_sni 51.20.98.153', 'https://51.20.98.153 {',
                    'issuer acme https://acme-v02.api.letsencrypt.org/directory {',
                    'profile shortlived', 'disable_http_challenge',
                    'reverse_proxy nginx:8080', 'redir https://51.20.98.153{uri} 308']:
                    self.assertIn(expected, config)
                self.assertNotIn('disable_tlsalpn_challenge', config)
                self.assertNotIn('tls internal', config)

    def test_invalid_or_mismatched_ip_never_starts_caddy(self):
        for origin, ip in [
            ('https://51.20.98.153', '51.20.98.999'),
            ('https://51.20.98.153', '051.20.98.153'),
            ('https://51.20.98.153', '51.20..153'),
            ('https://51.20.98.153', '51.20.98.153\n51.20.98.153'),
            ('https://51.20.98.153', '51.20.98.153\n}'),
            ('https://51.20.98.153:8443', '51.20.98.153'),
            ('https://other.example.com', '51.20.98.153'),
            ('http://51.20.98.153', '51.20.98.153'),
        ]:
            with self.subTest(origin=origin, ip=ip):
                self.assertNotEqual(self.run_edge(origin, ip).returncode, 0)
                self.assertFalse(self.args.exists())
                self.assertFalse(self.config.exists())


if __name__ == '__main__':
    unittest.main()
