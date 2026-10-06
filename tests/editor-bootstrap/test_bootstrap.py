"""Offline lifecycle tests; all downloads/editor launches are replaced by fixtures."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'apps/web/public/tunnex-editor.sh'

class BootstrapTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.client = b'#!/bin/sh\nif [ "$1" = help ]; then echo "tunnex editor"; else echo "$*" >> "$HOME/launched"; fi\n'
        (self.root / 'asset').write_bytes(self.client)
        self.digest = hashlib.sha256(self.client).hexdigest()
        (self.root / 'hash').write_text(self.digest)
        self.tool('curl', '''case "$*" in *.sha256*) src="$HOME/hash" ;; *) src="$HOME/asset" ;; esac
while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then cp "$src" "$2"; exit; fi; shift; done
exit 1''')
        self.tool('code', '''if [ "$1" = --list-extensions ]; then [ ! -f "$HOME/extension" ] || echo ms-vscode-remote.remote-ssh; else touch "$HOME/extension"; fi''')
        self.env = dict(os.environ, HOME=str(self.root), PATH=f'{self.bin}:/usr/bin:/bin')
    def tearDown(self):
        self.tmp.cleanup()
    def tool(self, name, body):
        p = self.bin / name
        p.write_text('#!/bin/sh\nset -eu\n' + body + '\n')
        p.chmod(0o700)
    def run_bootstrap(self):
        return subprocess.run(['sh', str(SCRIPT), '--server', 'https://console.test', '--org', 'org', '--target', 'server', '--account', 'ubuntu'], env=self.env, capture_output=True, text=True)
    def test_install_then_reuse_without_binary_download(self):
        self.assertEqual(self.run_bootstrap().returncode, 0)
        installed = self.root / '.local/share/tunnex/editor-client' / self.digest / 'tunnex'
        self.assertEqual(installed.read_bytes(), self.client)
        (self.root / 'asset').unlink()
        self.assertEqual(self.run_bootstrap().returncode, 0)
        self.assertEqual(len((self.root / 'launched').read_text().splitlines()), 2)
        self.assertTrue((self.root / 'extension').exists())
    def test_new_build_updates_managed_client(self):
        self.assertEqual(self.run_bootstrap().returncode, 0)
        new = self.client + b'# next version\n'
        digest = hashlib.sha256(new).hexdigest()
        (self.root / 'asset').write_bytes(new)
        (self.root / 'hash').write_text(digest)
        self.assertEqual(self.run_bootstrap().returncode, 0)
        self.assertTrue((self.root / '.local/share/tunnex/editor-client' / digest / 'tunnex').exists())
    def test_tampered_download_does_not_launch(self):
        (self.root / 'asset').write_bytes(b'tampered')
        self.assertNotEqual(self.run_bootstrap().returncode, 0)
        self.assertFalse((self.root / 'launched').exists())
    def test_download_failure_does_not_launch(self):
        self.tool('curl', 'exit 22')
        self.assertNotEqual(self.run_bootstrap().returncode, 0)
        self.assertFalse((self.root / 'launched').exists())
    def test_symlinked_install_directory_refused(self):
        (self.root / '.local').symlink_to(self.bin)
        self.assertNotEqual(self.run_bootstrap().returncode, 0)
        self.assertFalse((self.root / 'launched').exists())

if __name__ == '__main__':
    unittest.main()
