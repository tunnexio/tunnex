import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import delivery


HERE = Path(__file__).resolve().parent
LOCK = HERE / "ubuntu26-amd64.lock.json"


def fixture_lock():
    lock = delivery.read_json(LOCK)
    for record in lock["metadata"] + lock["download_packages"]:
        raw = (record["path"] + " public fixture\n").encode()
        record["sha256"], record["size"] = delivery.sha256(raw), len(raw)
        if record in lock["download_packages"]:
            record["path"] = "packages/" + record["sha256"] + ".deb"
    return lock


def create_cache(lock, root):
    for record in lock["metadata"] + lock["download_packages"]:
        # Package fixture bytes refer to their original public metadata path.
        if record in lock["download_packages"]:
            original = next(p for p in delivery.read_json(LOCK)["download_packages"]
                            if p["name"] == record["name"])
            raw = (original["path"] + " public fixture\n").encode()
        else:
            raw = (record["path"] + " public fixture\n").encode()
        path = root / record["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


class LockTests(unittest.TestCase):
    def test_public_lock_has_complete_pinned_signed_input_set(self):
        lock = delivery.read_json(LOCK)
        self.assertEqual(delivery.validate_lock(lock), "amd64")
        self.assertEqual(len(lock["download_packages"]), 55)
        self.assertEqual(len(lock["metadata"]), 9)
        self.assertFalse(lock["native_qualification"])
        for record in lock["download_packages"]:
            self.assertTrue(record["url"].startswith("https://snapshot.ubuntu.com/ubuntu/20261001T000000Z/pool/"))

    def test_mutable_base_missing_essential_and_invented_qualification_refused(self):
        for mutation in (lambda p: p["base_images"].update(amd64="ubuntu:26.04"),
                         lambda p: p["packages"].remove("wireguard-tools"),
                         lambda p: p.update(native_qualification=True),
                         lambda p: p.update(architecture="mips")):
            lock = delivery.read_json(LOCK)
            mutation(lock)
            with self.assertRaises(delivery.InvalidInput):
                delivery.validate_lock(lock)

    def test_package_corruption_paths_redirects_and_inventory_drift_refused(self):
        cases = (
            lambda p: p["download_packages"][0].update(sha256="x" * 64),
            lambda p: p["download_packages"][0].update(path="../operator-config"),
            lambda p: p["download_packages"][0].update(url="https://example.org/file"),
            lambda p: p["download_packages"][0].update(version="2.0\nsecret"),
            lambda p: p["metadata"].pop(),
            lambda p: p["metadata"][0].update(path="repository/dists/other/InRelease"),
            lambda p: p["download_packages"].append(p["download_packages"][0]),
            lambda p: p["installed_inventory"].remove(next(row for row in p["installed_inventory"]
                                                          if row.startswith("wireguard-tools\t"))),
        )
        for mutation in cases:
            with self.subTest(mutation=mutation):
                lock = delivery.read_json(LOCK)
                mutation(lock)
                with self.assertRaises(delivery.InvalidInput):
                    delivery.validate_lock(lock)

    def test_json_duplicate_fields_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"version":1,"version":2}')
            with self.assertRaises(delivery.InvalidInput):
                delivery.read_json(path)

    def test_nonpublic_fields_in_lock_are_refused(self):
        lock = delivery.read_json(LOCK)
        lock["operator_credential"] = "synthetic"
        with self.assertRaises(delivery.InvalidInput):
            delivery.validate_lock(lock)

    def test_cached_input_is_verified_without_network_and_bad_cache_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "input.deb"
            raw = b"public package fixture"
            target.write_bytes(raw)
            record = dict(sha256=delivery.sha256(raw), size=len(raw))
            with patch("urllib.request.urlopen") as opened:
                self.assertEqual(delivery.download("https://snapshot.ubuntu.com/file", target, record), raw)
                opened.assert_not_called()
                target.write_bytes(raw + b"corrupt")
                with self.assertRaises(delivery.InvalidInput):
                    delivery.download("https://snapshot.ubuntu.com/file", target, record)
                opened.assert_not_called()

    def test_symlinked_cache_refused_before_consuming_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "real"
            target.write_bytes(b"fixture")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaises(delivery.InvalidInput):
                delivery.verify(link, dict(size=7, sha256=delivery.sha256(b"fixture")))


class BuildTests(unittest.TestCase):
    def test_dependency_context_contains_only_verified_public_inputs_and_network_is_off(self):
        lock = fixture_lock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            create_cache(lock, cache)
            (cache / "unrelated-private-fixture").write_text("must not be copied")
            lock_path = root / "lock.json"
            delivery.write_json(lock_path, lock)
            events = []

            def fake_run(args, **kwargs):
                events.append(args)
                if args[1:3] == ["image", "inspect"]:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps([
                        {"Architecture": "amd64", "Os": "linux", "Id": "sha256:" + "a" * 64}]))
                self.assertEqual(args[1], "build")
                self.assertIn("--network=none", args)
                self.assertIn("--pull=false", args)
                context = Path(args[-1])
                expected = {"Containerfile", "expected-inventory.tsv"} | {
                    "packages/" + delivery.package_filename(p) for p in lock["download_packages"]}
                self.assertEqual({str(path.relative_to(context)) for path in context.rglob("*") if path.is_file()}, expected)
                self.assertIn("--no-download --no-install-recommends", (context / "Containerfile").read_text())
                self.assertIn("exit 101", (context / "Containerfile").read_text())
                return subprocess.CompletedProcess(args, 0)

            with patch.object(delivery, "run", side_effect=fake_run):
                result = delivery.build_base(lock_path, cache, "tunnex-sandbox-fixture", "docker")
            self.assertFalse(result["native_qualification"])
            self.assertEqual(len(events), 3)

    def test_corrupt_input_stops_before_engine_inspection_or_build(self):
        lock = fixture_lock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_cache(lock, root / "cache")
            (root / "cache" / lock["download_packages"][0]["path"]).write_bytes(b"corrupt")
            lock_path = root / "lock.json"
            delivery.write_json(lock_path, lock)
            with patch.object(delivery, "run") as runner, self.assertRaises(delivery.InvalidInput):
                delivery.build_base(lock_path, root / "cache", "tunnex-sandbox-fixture", "docker")
            runner.assert_not_called()

    def test_public_registry_operations_never_consult_saved_auth(self):
        for engine in ("docker", "podman"):
            for action in ("pull", "build"):
                with self.subTest(engine=engine, action=action):
                    def inspect(args, **kwargs):
                        if engine == "docker":
                            self.assertEqual(args[:2], [engine, "--config"])
                            config = Path(args[2]) / "config.json"
                        else:
                            self.assertEqual(args[:3], [engine, action, "--authfile"])
                            config = Path(args[3])
                        data = json.loads(config.read_text())
                        self.assertEqual(data["auths"], {})
                        self.assertNotIn("credsStore", data)
                        self.assertNotIn("credHelpers", data)
                        self.assertTrue(set(data) <= {"auths", "cliPluginsExtraDirs"})
                        return subprocess.CompletedProcess(args, 0)
                    with patch("subprocess.run", side_effect=inspect):
                        delivery.run([engine, action, "public-input"])


if __name__ == "__main__":
    unittest.main()
