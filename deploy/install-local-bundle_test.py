#!/usr/bin/env python3
"""Signed local bundle contracts; real signatures, mocked Docker, no network."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

DEPLOY = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bundle", DEPLOY / "install-bundle.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class LocalBundle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="tunnex-bundle-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.payload = self.root / "payload"
        self.payload.mkdir()
        self.key = self.root / "trusted.pem"
        self.private = self.root / "private.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout", "-out", str(self.key)], check=True, capture_output=True)
        self.manifest = dict(schema_version=1, kind=bundle.KIND, platform="linux/amd64", source_sha="a" * 40, version="0.1.42-local.1", files={}, images={}, client=dict(path="client/Tunnex-local.pkg", source_sha="b" * 40, version="0.1.14-local.1", platform="darwin/universal"))
        for name in bundle.PAYLOAD:
            dst = self.payload / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(DEPLOY.parent / name, dst)
        for index, role in enumerate(sorted(bundle.ROLES), 1):
            name = f"images/{role}.tar"
            dst = self.payload / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes((f"mock archive {role}\n").encode())
            self.manifest["images"][role] = dict(archive=name, image_id="sha256:" + format(index, "064x"), os="linux", architecture="amd64", source_sha="a" * 40 if role in bundle.PRODUCT_ROLES else None)
        client = self.payload / self.manifest["client"]["path"]
        client.parent.mkdir(parents=True)
        client.write_bytes(b"mock universal client package\n")
        self.refresh_files()
        self.sign()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "docker").write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with open(os.environ['DOCKER_LOG'],'a') as f:f.write(json.dumps(args)+'\\n')
if args[:1]==['info']:
 if '--format' in args:print(os.environ.get('MOCK_SERVER_PLATFORM','linux/x86_64'))
elif args[:2]==['image','load']:sys.stdin.buffer.read()
elif args[:2]==['image','inspect']:
 print(json.dumps([dict(Id=os.environ.get('MOCK_IMAGE_ID',args[2]),Os='linux',Architecture=os.environ.get('MOCK_IMAGE_ARCH','amd64'))]))
elif args[:2]==['compose','version']:print('Docker Compose version v2.fixture')
elif args[:2]==['ps','-aq']:
 if os.environ.get('MOCK_QUERY_FAILURE')=='containers':raise SystemExit(2)
 print(os.environ.get('MOCK_EXISTING_PROJECT',''))
elif args[:2]==['volume','ls']:
 if os.environ.get('MOCK_QUERY_FAILURE')=='volumes':raise SystemExit(2)
 if '--format' in args:
  if os.environ.get('MOCK_NAMED_VOLUME'):print(json.dumps(os.environ['MOCK_NAMED_VOLUME']))
 else:print(os.environ.get('MOCK_EXISTING_VOLUMES',''))
elif args[:1]==['compose']:
 if 'pull' in args:raise SystemExit('Unexpected registry pull')
 if 'up' in args:
  assert '--pull' in args and args[args.index('--pull')+1]=='never'
  Path(os.environ['FIRST_START_ENV']).write_text(Path('.env').read_text())
 elif 'config' in args:
  roles={'api':'API','web':'WEB','nginx':'NGINX','node-agent':'NODE_AGENT','bifrost':'AI_ENGINE','ai-egress':'API','postgres':'POSTGRES','redis':'REDIS','caddy':'CADDY'}
  services={k:{'image':os.environ['TUNNEX_'+v+'_IMAGE']} for k,v in roles.items()}
  services['api']['environment']={key:os.environ[key] for key in ('TUNNEX_NODE_AGENT_IMAGE','TUNNEX_RELEASE_UPDATE_CHECK','TUNNEX_RELEASE_MANIFEST_PATH','TUNNEX_RELEASE_CATALOG_URL')}
  if os.environ.get('MOCK_RESOLVED_IMAGE'):services['api']['image']=os.environ['MOCK_RESOLVED_IMAGE']
  print(json.dumps({'services':services,'volumes':{'postgres_data':{'name':'local_bundle_fixture_postgres_data'},'server_access_recordings':{'name':os.environ.get('TUNNEX_SERVER_ACCESS_RECORDING_VOLUME','local_bundle_fixture_server_access_recordings')}}}))
 elif 'logs' not in args:raise SystemExit('Unexpected Compose command')
else:raise SystemExit('Unexpected Docker command')
''')
        (self.bin / "curl").write_text('#!/bin/sh\nprintf "Unexpected network request" >&2\nexit 98\n')
        (self.bin / "uname").write_text('#!/bin/sh\nprintf "Linux\\n"\n')
        for file in self.bin.iterdir():
            file.chmod(0o755)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("TUNNEX_")}
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ["PATH"], DOCKER_LOG=str(self.root / "docker.jsonl"), FIRST_START_ENV=str(self.root / "first-start.env"), NO_COLOR="1", TUNNEX_LOCAL_BUNDLE_DIR=str(self.payload), TUNNEX_LOCAL_BUNDLE_PUBLIC_KEY=str(self.key), TUNNEX_DIR=str(self.root / "installed"), TUNNEX_PUBLIC_BASE_URL="http://192.0.2.20", TUNNEX_ADMIN_EMAIL="admin@example.invalid", TUNNEX_SMTP="skip", TUNNEX_BOOTSTRAP_ORG_NAME="Private qualification", TUNNEX_GATEWAY_PLACEMENT="separate", TUNNEX_COMPOSE_PROJECT="local_bundle_fixture", TUNNEX_TEST_TTY_DEVICE=str(self.root / "no-tty"))

    def refresh_files(self):
        self.manifest["files"] = {str(file.relative_to(self.payload)): {"bytes": file.stat().st_size, "sha256": bundle.digest(file)} for file in self.payload.rglob("*") if file.is_file() and file.name not in ("bundle.json", "bundle.json.sig")}

    def sign(self):
        path = self.payload / "bundle.json"
        path.write_text(json.dumps(self.manifest, sort_keys=True))
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.private), "-in", str(path), "-out", str(self.payload / "bundle.json.sig")], check=True, capture_output=True)

    def invoke(self, action="verify", **changes):
        env = dict(self.env, **changes)
        command = ["python3", str(self.payload / "deploy/install-bundle.py"), action, "--bundle", str(self.payload), "--public-key", env["TUNNEX_LOCAL_BUNDLE_PUBLIC_KEY"]]
        if action == "verify":
            command += ["--stage", str(self.root / "stage")]
        return subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)

    def test_real_signature_and_all_artifacts(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["result"], "VERIFIED_LOCAL_BUNDLE")
        self.assertEqual(receipt["bundle_sha256"], bundle.digest(self.payload / "bundle.json"))
        self.assertEqual((self.root / "stage/client/Tunnex-local.pkg").read_bytes(), b"mock universal client package\n")

    def test_signature_tampering_fails_before_docker(self):
        with (self.payload / "bundle.json").open("ab") as f:
            f.write(b" ")
        result = self.invoke("load")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature verification failed", result.stderr)
        self.assertFalse((self.root / "docker.jsonl").exists())

    def test_does_not_trust_bundled_key(self):
        copied = self.payload / "key.pem"
        shutil.copyfile(self.key, copied)
        result = self.invoke(TUNNEX_LOCAL_BUNDLE_PUBLIC_KEY=str(copied))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("independently", result.stderr)

    def test_missing_or_corrupt_archive_refused(self):
        (self.payload / "images/node-agent.tar").write_bytes(b"different archive")
        result = self.invoke("load")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertFalse((self.root / "docker.jsonl").exists())

    def test_unsafe_path_symlink_and_missing_image_refused(self):
        for mode in ("path", "symlink", "missing-role", "source", "platform", "unknown", "client"):
            with self.subTest(mode=mode):
                original = json.loads(json.dumps(self.manifest))
                if mode == "path":
                    self.manifest["files"]["../outside"] = {"bytes": 1, "sha256": "a" * 64}
                elif mode == "symlink":
                    file = self.payload / "images/api.tar"
                    data = file.read_bytes(); file.unlink(); file.symlink_to(self.private)
                elif mode == "missing-role":
                    del self.manifest["images"]["web"]
                elif mode == "source":
                    self.manifest["images"]["api"]["source_sha"] = "c" * 40
                elif mode == "platform":
                    self.manifest["platform"] = "linux/arm64"
                elif mode == "unknown":
                    self.manifest["ignore_signature"] = True
                else:
                    self.manifest["client"]["path"] = "missing.pkg"
                self.sign()
                self.assertNotEqual(self.invoke().returncode, 0)
                self.manifest = original
                if mode == "symlink":
                    file.unlink(); file.write_bytes(data)
        self.sign()

    def test_loaded_identity_and_platform_are_checked(self):
        for env in ({"MOCK_IMAGE_ID": "sha256:" + "f" * 64}, {"MOCK_IMAGE_ARCH": "arm64"}, {"MOCK_SERVER_PLATFORM": "linux/aarch64"}):
            with self.subTest(env=env):
                self.assertNotEqual(self.invoke("load", **env).returncode, 0)
        result = self.invoke("load")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(json.loads(result.stdout)["images"]), bundle.ROLES)

    def test_gateway_load_selects_exact_signed_id(self):
        result = self.invoke("gateway-load")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["images"], {"node-agent": self.manifest["images"]["node-agent"]["image_id"]})

    def test_actual_installer_first_start_has_all_pins_without_network(self):
        result = subprocess.run(["sh", str(self.payload / "deploy/install.sh"), "--yes"], env=dict(self.env, TUNNEX_API_IMAGE="untrusted:override", TUNNEX_AI_ENGINE_IMAGE="untrusted:ai", TUNNEX_RELEASE_MANIFEST_PATH="/old/release.json", TUNNEX_RELEASE_UPDATE_CHECK="true", TUNNEX_RELEASE_CATALOG_URL="https://old.invalid/catalog"), cwd=self.root, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        first = dict(line.split("=", 1) for line in (self.root / "first-start.env").read_text().splitlines() if "=" in line)
        for role, image in self.manifest["images"].items():
            self.assertEqual(first["TUNNEX_" + role.upper().replace("-", "_") + "_IMAGE"], image["image_id"])
        self.assertEqual(first["TUNNEX_RELEASE_UPDATE_CHECK"], "false")
        self.assertEqual(first["TUNNEX_RELEASE_MANIFEST_PATH"], "")
        self.assertIn("Mac client:", result.stdout)
        self.assertTrue((self.root / "installed/local-bundle/client/Tunnex-local.pkg").is_file())
        self.assertNotEqual(subprocess.run(["sh", str(self.root / "installed/upgrade.sh")], capture_output=True).returncode, 0)
        again = subprocess.run(["sh", str(self.payload / "deploy/install.sh"), "--yes"], env=self.env, cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("fresh installation", again.stderr)

    def test_existing_project_is_not_reused(self):
        env = dict(self.env, MOCK_EXISTING_PROJECT="foreign-existing-container")
        result = subprocess.run(["sh", str(self.payload / "deploy/install.sh"), "--yes"], env=env, cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already has containers", result.stderr)
        self.assertFalse((self.root / "first-start.env").exists())

    def test_existing_data_volume_is_not_reused(self):
        env = dict(self.env, MOCK_EXISTING_VOLUMES="retained-postgres-volume")
        result = subprocess.run(["sh", str(self.payload / "deploy/install.sh"), "--yes"], env=env, cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already has data volumes", result.stderr)
        self.assertFalse((self.root / "first-start.env").exists())

    def test_wrong_independent_key_refused(self):
        other = self.root / "other-private.pem"
        pub = self.root / "other.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(other)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(other), "-pubout", "-out", str(pub)], check=True, capture_output=True)
        self.assertNotEqual(self.invoke(TUNNEX_LOCAL_BUNDLE_PUBLIC_KEY=str(pub)).returncode, 0)

    def test_gateway_preview_uses_same_signature_without_host_mutation(self):
        result = subprocess.run(["sh", str(self.payload / "deploy/install.sh"), "--gateway-bundle", "--dry-run"], env=self.env, cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.manifest["images"]["node-agent"]["image_id"], result.stdout)
        calls = [json.loads(line) for line in (self.root / "docker.jsonl").read_text().splitlines()]
        self.assertEqual(calls, [["compose", "version"]])
        self.assertFalse((self.root / "installed").exists())

    def test_bundle_cannot_change_between_verify_and_load(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = json.loads(result.stdout)["bundle_sha256"]
        self.manifest["version"] = "0.1.42-local.2"
        self.sign()
        result = subprocess.run(["python3", str(self.payload / "deploy/install-bundle.py"), "load", "--bundle", str(self.payload), "--public-key", str(self.key), "--expected-sha256", expected], env=self.env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changed after initial verification", result.stderr)
        self.assertFalse((self.root / "docker.jsonl").exists())

    def test_failed_docker_inventory_is_not_an_empty_project(self):
        for mode in ("containers", "volumes"):
            for gateway in (False, True):
                with self.subTest(mode=mode, gateway=gateway):
                    command = ["sh", str(self.payload / "deploy/install.sh"), "--yes"] + (["--gateway-bundle"] if gateway else [])
                    result = subprocess.run(command, env=dict(self.env, MOCK_QUERY_FAILURE=mode), cwd=self.root, capture_output=True, text=True, timeout=30)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Could not inspect existing", result.stderr)
                    self.assertFalse((self.root / "first-start.env").exists())

    def test_resolved_unlabelled_volume_and_image_mismatch_refused(self):
        for name, extra in (("local_bundle_fixture_postgres_data", {}), ("custom_recordings", {"TUNNEX_SERVER_ACCESS_RECORDING_VOLUME": "custom_recordings"}), ("", {"MOCK_RESOLVED_IMAGE": "unverified:api"})):
            with self.subTest(name=name):
                target = self.root / "installed"
                if target.exists():
                    shutil.rmtree(target)
                result = subprocess.run(["sh", str(self.payload / "deploy/install.sh"), "--yes"], env=dict(self.env, MOCK_NAMED_VOLUME=name, **extra), cwd=self.root, capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Local Compose image or fresh-volume verification failed", result.stderr)
                self.assertFalse((self.root / "first-start.env").exists())
                calls = [json.loads(line) for line in (self.root / "docker.jsonl").read_text().splitlines()]
                self.assertNotIn(["image", "load"], calls)


if __name__ == "__main__":
    unittest.main()
