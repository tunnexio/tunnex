"""AA-EN-1 stop-gap renew: validate a renewed public pair, install it with the
right mode and ownership, restart the proxy in a controlled way, and restore
the previous pair if the proxy does not become ready.

Certificates are made with the openssl CLI at test time only; the command
itself uses the Python standard library. Docker is faked.
"""
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
TOOL = ROOT / "deploy/app-access/tunnex-app-access.py"
OPENSSL = shutil.which("openssl")

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
d = os.environ["FAKE_DIR"]
args = sys.argv[1:]
with open(os.path.join(d, "calls"), "a") as log:
    log.write(" ".join(args) + "\n")
if args[0] == "ps":
    print("proxy1")
elif args[0] == "inspect" and "Config.Labels" in args[2]:
    labels = {"com.docker.compose.project": "tunnex", "com.docker.compose.service": "app-proxy", "com.docker.compose.oneoff": "False"}
    print("%s|%s|%s" % (json.dumps(labels), "[]", "{}"))
elif args[0] == "inspect":
    states = open(os.path.join(d, "health")).read().split("\n")
    print(states[0])
    if len(states) > 1:
        open(os.path.join(d, "health"), "w").write("\n".join(states[1:]))
elif args[0] == "restart":
    # Record which leaf the proxy would load on this start.
    with open(os.path.join(d, "restarts"), "a") as f:
        f.write(open(os.path.join(os.environ["SECRETS"], "public-cert.pem")).read().split("\n")[1][:40] + "\n")
else:
    sys.exit("unexpected docker call: %s" % args)
'''


def openssl(*args, cwd):
    subprocess.run([OPENSSL, *args], cwd=cwd, check=True, capture_output=True)


def supports_validity_dates():
    help_text = subprocess.run([OPENSSL, "x509", "-help"], capture_output=True, text=True)
    return "-not_after" in help_text.stdout + help_text.stderr


@unittest.skipUnless(OPENSSL, "openssl CLI makes test certificates")
class Renew(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.pki = self.tmp / "pki"
        self.dir = self.tmp / "tunnex"
        self.secrets = self.tmp / "secrets"
        self.fake = self.tmp / "fake"
        self.bin = self.tmp / "bin"
        for d in (self.pki, self.dir, self.secrets, self.fake, self.bin):
            d.mkdir()
        self.secrets.chmod(0o700)
        (self.bin / "docker").write_text(FAKE_DOCKER)
        (self.bin / "docker").chmod(0o755)
        (self.fake / "health").write_text("running healthy")
        (self.dir / ".env").write_text(
            "APP_BASE_URL=https://cp.example.test\nTUNNEX_APP_ACCESS_BASE_DOMAIN=cp.example.test\n"
            "TUNNEX_APP_PROXY_SECRETS_DIR=%s\nTUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL=https://caddy:443\n" % self.secrets)
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "root.key",
                "-out", "root.pem", "-subj", "/CN=AA-EN-1 test root", "-days", "30",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=self.pki)
        # RFC 5280-shaped fixtures: strict verifiers (VERIFY_X509_STRICT, the
        # Python 3.13+ default) require key identifiers, as real CAs issue them.
        (self.pki / "inter.ext").write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
                                            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "inter.key",
                "-out", "inter.csr", "-subj", "/CN=AA-EN-1 test intermediate", cwd=self.pki)
        openssl("x509", "-req", "-in", "inter.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial",
                "-out", "inter.pem", "-days", "30", "-extfile", "inter.ext", cwd=self.pki)
        # The installed pair: valid, shorter-lived than a renewal.
        self.leaf("installed", days=10)
        for name in ("cert", "key"):
            src = self.pki / ("installed-fullchain.pem" if name == "cert" else "installed.key")
            dst = self.secrets / ("public-%s.pem" % name)
            shutil.copy(src, dst)
            dst.chmod(0o400)

    def leaf(self, name, days=20, sans="DNS:*.cp.example.test,DNS:cp.example.test", dates=None):
        (self.pki / (name + ".ext")).write_text("basicConstraints=critical,CA:FALSE\nsubjectAltName=%s\nextendedKeyUsage=serverAuth\n"
                                                "keyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\n"
                                                "authorityKeyIdentifier=keyid\n" % sans)
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", name + ".key",
                "-out", name + ".csr", "-subj", "/CN=cp.example.test", cwd=self.pki)
        validity = ["-days", str(days)] if dates is None else ["-not_before", dates[0], "-not_after", dates[1]]
        openssl("x509", "-req", "-in", name + ".csr", "-CA", "inter.pem", "-CAkey", "inter.key", "-CAcreateserial",
                "-out", name + ".pem", *validity, "-extfile", name + ".ext", cwd=self.pki)
        (self.pki / (name + "-fullchain.pem")).write_text((self.pki / (name + ".pem")).read_text() + (self.pki / "inter.pem").read_text())
        return self.pki / (name + "-fullchain.pem"), self.pki / (name + ".key")

    def run_tool(self, cert, key, *extra):
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), FAKE_DIR=str(self.fake), SECRETS=str(self.secrets))
        return subprocess.run([sys.executable, "-B", str(TOOL), "--directory", str(self.dir), "renew", "--cert", str(cert),
                               "--key", str(key), "--ca-file", str(self.pki / "root.pem"), "--restart-timeout", "5", *extra],
                              capture_output=True, text=True, env=env)

    def installed(self):
        return {n: (self.secrets / n).read_bytes() for n in ("public-cert.pem", "public-key.pem")}

    def test_dry_run_validates_and_changes_nothing(self):
        cert, key = self.leaf("renewed")
        before = self.installed()
        r = self.run_tool(cert, key)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("dry run", r.stdout)
        self.assertIn("cp.example.test", r.stdout)
        self.assertNotIn("PRIVATE KEY", r.stdout + r.stderr)
        self.assertEqual(before, self.installed())
        self.assertNotIn("restart", (self.fake / "calls").read_text() if (self.fake / "calls").exists() else "")

    def test_apply_installs_0400_restarts_and_keeps_previous(self):
        cert, key = self.leaf("renewed")
        previous = self.installed()
        r = self.run_tool(cert, key, "--apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.secrets / "public-cert.pem").read_bytes(), cert.read_bytes())
        self.assertEqual((self.secrets / "public-key.pem").read_bytes(), key.read_bytes())
        for name in ("public-cert.pem", "public-key.pem"):
            st = (self.secrets / name).stat()
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o400)
            self.assertEqual(st.st_uid, os.getuid())  # the existing owner (uid 10001 on a host) is kept
            self.assertEqual((self.secrets / (name + ".previous")).read_bytes(), previous[name])
            self.assertFalse((self.secrets / (name + ".next")).exists())
        self.assertIn("restart --time 10 proxy1", (self.fake / "calls").read_text())
        self.assertNotIn("PRIVATE KEY", r.stdout + r.stderr)

    def test_proxy_not_ready_restores_previous_pair(self):
        cert, key = self.leaf("renewed")
        previous = self.installed()
        (self.fake / "health").write_text("exited\nrunning healthy")
        r = self.run_tool(cert, key, "--apply")
        self.assertEqual(r.returncode, 13)
        self.assertIn("previous files were restored", r.stderr)
        self.assertNotIn("Nothing was changed", r.stderr)
        self.assertEqual(previous, self.installed())
        self.assertEqual(len((self.fake / "restarts").read_text().splitlines()), 2)

    def test_invalid_pairs_are_refused_before_any_change(self):
        cases = {
            "key mismatch": lambda: (self.leaf("a")[0], self.leaf("b")[1]),
            "hostname": lambda: self.leaf("other", sans="DNS:*.elsewhere.test,DNS:cp.example.test"),
            "portal not covered": lambda: self.leaf("noportal", sans="DNS:*.cp.example.test"),
            "chain": lambda: (self.pki / "leafonly.pem", self.leaf("leafonly")[1]),
            "earlier expiry": lambda: self.leaf("short", days=9),
            "too short": lambda: self.leaf("tiny", days=3),
        }
        expected = {"key mismatch": "do not match", "hostname": "does not verify", "portal not covered": "cp.example.test",
                    "chain": "does not verify", "earlier expiry": "not later than the installed",
                    "too short": "less than 7 days"}
        if supports_validity_dates():
            cases["expired"] = lambda: self.leaf("expired", dates=("20200101000000Z", "20200201000000Z"))
            cases["not yet valid"] = lambda: self.leaf("future", dates=("20990101000000Z", "20990201000000Z"))
            expected["expired"] = expected["not yet valid"] = "does not verify"
        before = self.installed()
        for name, make in cases.items():
            with self.subTest(name):
                cert, key = make()
                r = self.run_tool(cert, key, "--apply")
                self.assertEqual(r.returncode, 13, r.stdout)
                self.assertIn(expected[name], r.stderr)
                self.assertIn("Nothing was changed", r.stderr)
                self.assertEqual(before, self.installed())
        self.assertFalse((self.fake / "restarts").exists())

    def test_earlier_expiry_needs_explicit_flag(self):
        cert, key = self.leaf("short", days=9)
        r = self.run_tool(cert, key, "--apply", "--allow-earlier-expiry")
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
