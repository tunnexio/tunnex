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
        self.image = service.split('    image: ', 1)[1].splitlines()[0]
        self.script = textwrap.dedent(service.split('    command:\n      - |\n', 1)[1].split('    ports:', 1)[0]).replace('$$', '$').replace('/tmp/tunnex-Caddyfile', str(self.config))

    def run_edge(self, origin, ip='', http_console='false', mode='', peers=''):
        self.args.unlink(missing_ok=True)
        self.config.unlink(missing_ok=True)
        return subprocess.run(['sh', '-ec', self.script], env={**os.environ,
            'PATH': str(self.root) + os.pathsep + os.environ['PATH'],
            'TEST_CADDY_ARGS': str(self.args),
            'TUNNEX_EDGE_LISTEN': origin, 'TUNNEX_EDGE_PUBLIC_IP': ip,
            'TUNNEX_HTTP_CONSOLE_ENABLED': http_console,
            'TUNNEX_TLS_MODE': mode, 'TUNNEX_EDGE_TRUSTED_PROXIES': peers},
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

    def test_explicit_http_console_keeps_https_site(self):
        for origin, ip in [('https://51.20.98.153', '51.20.98.153'),
                           ('https://vpn.example.com', '')]:
            with self.subTest(origin=origin):
                result = self.run_edge(origin, ip, 'true')
                self.assertEqual(result.returncode, 0, result.stderr)
                config = self.config.read_text()
                self.assertIn(origin + ' {', config)
                self.assertIn(':80 {\n  reverse_proxy nginx:8080\n}', config)
                self.assertNotIn('redir ', config)
        self.assertNotEqual(self.run_edge('http://:80', '', 'automatic').returncode, 0)

    def test_terminated_tls_trusts_only_explicit_proxy_peers(self):
        peers = '10.20.0.12/32 10.20.1.0/24 2001:db8::10/128'
        result = self.run_edge('http://:80', mode='terminated', peers=peers)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = self.config.read_text()
        self.assertIn('trusted_proxies static ' + peers, config)
        self.assertIn('@untrusted not remote_ip ' + peers, config)
        self.assertIn('respond @untrusted "Trusted TLS proxy required" 403', config)
        self.assertIn('not vars {http.request.header.X-Forwarded-Proto} http https', config)
        self.assertIn('not path /healthz', config)
        self.assertNotIn('header_up X-Forwarded-Proto https', config)
        self.assertEqual(self.args.read_text().splitlines(),
                         ['run', '--config', str(self.config), '--adapter', 'caddyfile'])

    def test_invalid_proxy_lists_fail_before_caddy_starts(self):
        for peers in ['', ' ', '0.0.0.0/0', '::/0', '10.0.0.1/00', '10.0.0.1/33',
                      '10.00.0.1', '10.0.0', '256.0.0.1', '::1/129', '1::2::3',
                      '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '2001:db8::/064',
                      'private_ranges', 'proxy.example.com', '10.0.0.1,10.0.0.2',
                      '10.0.0.1\n10.0.0.2', '10.0.0.1\t10.0.0.2', '10.0.0.1; id',
                      '10.0.0.1 }', '{$OTHER}', '$(touch /tmp/injection)']:
            with self.subTest(peers=peers):
                result = self.run_edge('http://:80', mode='terminated', peers=peers)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.args.exists())
                self.assertFalse(self.config.exists())
        self.assertNotEqual(self.run_edge('https://vpn.example.com', mode='terminated', peers='10.0.0.1').returncode, 0)

    def test_proxy_validation_matches_host_preflight(self):
        begin = '# BEGIN EXPLICIT EDGE PROXY VALIDATION'
        end = '# END EXPLICIT EDGE PROXY VALIDATION'
        expected = self.script.split(begin, 1)[1].split(end, 1)[0].strip()
        for name in ['install.sh', 'upgrade.sh']:
            source = Path(__file__).with_name(name).read_text()
            actual = source.split(begin, 1)[1].split(end, 1)[0].strip()
            self.assertEqual(actual, expected)

    @unittest.skipUnless(os.environ.get('TUNNEX_TEST_CADDY_RUNTIME') == '1',
                         'set TUNNEX_TEST_CADDY_RUNTIME=1 for isolated Docker probes')
    def test_actual_caddy_preserves_verified_scheme_and_rejects_spoofing(self):
        for peers, trusted in [('127.0.0.1/32', True), ('192.0.2.10/32', False)]:
            with self.subTest(peers=peers):
                result = self.run_edge('http://:80', mode='terminated', peers=peers)
                self.assertEqual(result.returncode, 0, result.stderr)
                config = self.config.read_text()
                adapted = subprocess.run(['docker', 'run', '--rm', '-i', '--network', 'none',
                    '--entrypoint', 'caddy', self.image, 'adapt', '--config', '/dev/stdin',
                    '--adapter', 'caddyfile', '--validate'], input=config, text=True,
                    capture_output=True, timeout=30)
                self.assertEqual(adapted.returncode, 0, adapted.stderr)
                # Both the edge and an echo upstream run inside one disposable,
                # network-isolated container. No ports or host mounts are exposed.
                config = config.replace(':80 {', ':18080 {').replace('nginx:8080', '127.0.0.1:18081')
                config += '\n:18081 {\n  respond "{http.request.header.X-Forwarded-Proto}"\n}\n'
                probe = r'''cat >/tmp/Caddyfile
caddy run --config /tmp/Caddyfile --adapter caddyfile >/tmp/caddy.log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
for attempt in 1 2 3 4 5; do
  if wget -qO- http://127.0.0.1:18081/ready >/dev/null 2>&1; then break; fi
  sleep 1
done
request() {
  rm -f /tmp/body /tmp/headers
  wget -S -O /tmp/body "$@" 2>/tmp/headers || true
  awk '$1 ~ /^HTTP\// { print $2 }' /tmp/headers | tail -1
}
'''
                if trusted:
                    probe += r'''[ "$(request --header 'X-Forwarded-Proto: https' http://127.0.0.1:18080/)" = 200 ]
[ "$(cat /tmp/body)" = https ]
[ "$(request --header 'X-Forwarded-Proto: http' http://127.0.0.1:18080/)" = 200 ]
[ "$(cat /tmp/body)" = http ]
[ "$(request http://127.0.0.1:18080/)" = 400 ]
[ "$(request --header 'X-Forwarded-Proto: https,http' http://127.0.0.1:18080/)" = 400 ]
[ "$(request --header 'X-Forwarded-Proto: https' --header 'X-Forwarded-Proto: http' http://127.0.0.1:18080/)" = 400 ]
[ "$(request http://127.0.0.1:18080/healthz)" = 200 ]
'''
                else:
                    probe += r'''[ "$(request --header 'X-Forwarded-Proto: https' http://127.0.0.1:18080/)" = 403 ]
'''
                checked = subprocess.run(['docker', 'run', '--rm', '-i', '--network', 'none',
                    '--entrypoint', 'sh', self.image, '-ec', probe], input=config, text=True,
                    capture_output=True, timeout=30)
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

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
