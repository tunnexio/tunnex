#!/usr/bin/env python3
"""Exercise the installer's actual capture against the API's real banner shape."""
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = (ROOT / 'deploy/install.sh').read_text()
BOOTSTRAP = (ROOT / 'apps/api/internal/bootstrap/bootstrap.go').read_text()
EMAIL = 'synthetic-admin@example.invalid'
PASSWORD = 'SYNTHETIC-ONLY-BOOTSTRAP-12345'


def bootstrap_banner():
    body = BOOTSTRAP.split('fmt.Fprint(out, "\\n"+', 1)[1].split('\n\n\tif mailer != nil', 1)[0]
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|\b(?:email|pw)\b', '"\\n"+' + body)
    return ''.join({'email': EMAIL, 'pw': PASSWORD}.get(token, '') if not token.startswith('"') else json.loads(token) for token in tokens)


def capture(log):
    function = ''
    if '# BEGIN BOOTSTRAP BANNER CAPTURE' in SOURCE:
        function = SOURCE.split('# BEGIN BOOTSTRAP BANNER CAPTURE', 1)[1].split('# END BOOTSTRAP BANNER CAPTURE', 1)[0]
    line = next(x for x in SOURCE.splitlines() if x.startswith('CREDS="$('))
    script = 'set -eu\ntunnex_compose() { cat; }\n' + function + '\n' + line + '\nprintf "%s" "$CREDS"\n'
    return subprocess.run(['sh', '-c', script], input=log, text=True, capture_output=True, timeout=5, check=True).stdout


class BootstrapBanner(unittest.TestCase):
    def test_real_source_banner_retains_both_credentials(self):
        output = capture(bootstrap_banner())
        self.assertIn('email     ' + EMAIL, output)
        self.assertIn('password  ' + PASSWORD, output)
        self.assertIn('SHOWN ONCE.', output)
        self.assertTrue(output.endswith('=' * 74))

    def test_compose_prefix_and_ansi_match_real_banner(self):
        for prefix in ('api-1  | ', '\x1b[36mtunnex-api-1  |\x1b[0m '):
            with self.subTest(prefix=prefix):
                log = ''.join(prefix + line + '\n' for line in bootstrap_banner().splitlines())
                output = capture('unrelated startup log\n' + log + 'unrelated later log\n')
                self.assertIn('email     ' + EMAIL, output)
                self.assertIn('password  ' + PASSWORD, output)
                self.assertNotIn('unrelated', output)
                self.assertNotIn('\x1b', output)

    def test_absent_banner_does_not_invent_or_capture_other_credentials(self):
        self.assertEqual(capture('api-1 | {"msg":"already bootstrapped"}\napi-1 | password  unrelated\n'), '')

    def test_incomplete_banner_is_not_presented_as_complete(self):
        banner = bootstrap_banner()
        self.assertEqual(capture(banner[:banner.rfind('=' * 74)]), '')


if __name__ == '__main__':
    unittest.main()
