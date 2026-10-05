"""Pure bundle integrity and publication guards; no host/provider/network calls."""

import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("sandbox_package", Path(__file__).with_name("package.py"))
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)
SOURCE = "a" * 40


def elf(arch):
    raw = bytearray(512)
    raw[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", raw, 18, package.ARCHITECTURES[arch])
    return bytes(raw)


def payload(arch):
    return {**{name: elf(arch) for name in package.binary_names(arch)},
            **{name: b"public fixture recipe\n" for name in package.ASSETS}}


def rewrite_bundle(raw, change):
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        files = [(member, archive.extractfile(member).read()) for member in archive.getmembers()]
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for member, content in change(files):
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content) if member.isfile() else None)
    return output.getvalue()


class PackageTests(unittest.TestCase):
    def bundle(self, arch="amd64"):
        return package.make_bundle(payload(arch), SOURCE, arch, "go version go1.26.8 linux/amd64")

    def write_architecture_bundles(self, root, mutate=None):
        for arch in package.ARCHITECTURES:
            parent = root / arch
            parent.mkdir()
            name = f"tunnex-sandbox-linux-{arch}.tar.gz"
            files = payload(arch)
            if mutate:
                mutate(arch, files)
            raw = package.make_bundle(files, SOURCE, arch, "fixture")
            (parent / name).write_bytes(raw)
            (parent / (name + ".sha256")).write_text(f"{package.digest(raw)}  {name}\n")

    def test_both_architectures_have_both_editions_and_no_qualification_claim(self):
        for arch in package.ARCHITECTURES:
            with self.subTest(arch=arch):
                result = package.inspect_bundle(self.bundle(arch), SOURCE, arch)
                self.assertEqual(result["api_editions"], ["open", "enterprise"])
                self.assertFalse(result["native_runtime_qualification"])
                self.assertFalse(result["workload_images_built"])
                self.assertEqual(len(package.binary_names(arch)), 8)

    def test_archive_is_reproducible(self):
        self.assertEqual(self.bundle(), self.bundle())

    def test_enrollment_distribution_pins_the_verified_bundle_bytes_and_actual_release_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundles = root / "bundles"
            bundles.mkdir()
            self.write_architecture_bundles(bundles)
            outputs = [root / "one", root / "two"]
            for output in outputs:
                package.distribution(bundles, SOURCE, "tunnexio/tunnex", f"tunnex-build-{SOURCE}", output)
            self.assertEqual({path.name for path in outputs[0].iterdir()}, {
                package.ENROLL_RELEASE_NAME, package.ENROLL_RELEASE_NAME + ".sha256",
                package.DISTRIBUTION_NAME, package.DISTRIBUTION_NAME + ".sha256",
            })
            for path in outputs[0].iterdir():
                self.assertEqual(path.read_bytes(), (outputs[1] / path.name).read_bytes())
            manifest = json.loads((outputs[0] / package.DISTRIBUTION_NAME).read_bytes())
            base = f"https://github.com/tunnexio/tunnex/releases/download/tunnex-build-{SOURCE}"
            self.assertEqual(manifest["source_sha"], SOURCE)
            self.assertEqual(manifest["bootstrap_script"], {
                "url": base + "/Tunnex-Sandbox-Enroll.py",
                "sha256": package.digest(payload("amd64")[package.ENROLL_SOURCE]),
            })
            self.assertEqual((outputs[0] / package.ENROLL_RELEASE_NAME).read_bytes(), payload("amd64")[package.ENROLL_SOURCE])
            for name in (package.ENROLL_RELEASE_NAME, package.DISTRIBUTION_NAME):
                self.assertEqual((outputs[0] / (name + ".sha256")).read_text(),
                                 f"{package.digest((outputs[0] / name).read_bytes())}  {name}\n")
            for arch in package.ARCHITECTURES:
                name = f"tunnex-sandbox-linux-{arch}.tar.gz"
                self.assertEqual(manifest["bundles"][arch], {
                    "url": base + "/" + name,
                    "sha256": package.digest((bundles / arch / name).read_bytes()),
                })
            self.assertEqual(manifest["installer_architectures"], ["amd64"])
            self.assertFalse(manifest["native_runtime_qualification"])
            self.assertFalse(manifest["workload_images_built"])
            self.assertNotIn("org_id", manifest)
            self.assertNotIn("credentials", manifest)

    def test_enrollment_distribution_refuses_mutable_or_foreign_release_names(self):
        for repository, tag in (("https://github.com/tunnexio/tunnex", "v1.2.3"),
                                ("tunnexio/tunnex/extra", "v1.2.3"),
                                ("tunnexio/tunnex", "main"),
                                ("tunnexio/tunnex", "latest"),
                                ("tunnexio/tunnex", "v1.2.3/other"),
                                ("tunnexio/tunnex", "v1.2.3?token=private"),
                                ("tunnexio/tunnex", "tunnex-build-" + "b" * 40)):
            with self.subTest(repository=repository, tag=tag), self.assertRaises(ValueError):
                package.distribution("unused", SOURCE, repository, tag, Path("/unused"))

    def test_enrollment_distribution_refuses_script_disagreement_and_existing_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundles = root / "bundles"
            bundles.mkdir()
            self.write_architecture_bundles(bundles, lambda arch, files: files.update(
                {package.ENROLL_SOURCE: b"different public script\n"}) if arch == "arm64" else None)
            with self.assertRaisesRegex(ValueError, "disagree"):
                package.distribution(bundles, SOURCE, "tunnexio/tunnex", "v1.2.3", root / "output")
            self.assertFalse((root / "output").exists())
            for path in bundles.rglob("*"):
                if path.is_file():
                    path.unlink()
            for arch in package.ARCHITECTURES:
                (bundles / arch).rmdir()
            self.write_architecture_bundles(bundles)
            existing = root / "existing"
            existing.mkdir()
            retained = existing / "operator.txt"
            retained.write_text("inert fixture")
            with self.assertRaises(FileExistsError):
                package.distribution(bundles, SOURCE, "tunnexio/tunnex", "v1.2.3", existing)
            self.assertEqual(retained.read_text(), "inert fixture")

    def test_enrollment_distribution_version_tag_is_url_encoded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundles = root / "bundles"
            bundles.mkdir()
            self.write_architecture_bundles(bundles)
            package.distribution(bundles, SOURCE, "tunnexio/tunnex", "v1.2.3+build.4", root / "output")
            manifest = json.loads((root / "output" / package.DISTRIBUTION_NAME).read_bytes())
            self.assertIn("/v1.2.3%2Bbuild.4/", manifest["bootstrap_script"]["url"])

    def test_unsupported_architecture_and_fabricated_source_refused(self):
        for arch, source in (("darwin", SOURCE), ("amd64", "a" * 7), ("arm64", "G" * 40)):
            with self.subTest(arch=arch, source=source), self.assertRaises(ValueError):
                package.make_bundle(payload("amd64"), source, arch, "fixture")

    def test_private_or_operational_files_cannot_enter_bundle(self):
        for name in ("worker/config.json", "controller-key.pem", "walk-artifacts/live.json", "deploy/sandbox/qualification/tunnex-sandbox-qual-actor.service"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "allowlist"):
                package.make_bundle(dict(payload("amd64"), **{name: b"inert private fixture"}), SOURCE, "amd64", "fixture")

    def test_missing_binary_and_wrong_architecture_refused(self):
        files = payload("amd64")
        files.pop(package.binary_names("amd64")[0])
        with self.assertRaisesRegex(ValueError, "allowlist"):
            package.make_bundle(files, SOURCE, "amd64", "fixture")
        files = payload("amd64")
        files[package.binary_names("amd64")[0]] = elf("arm64")
        with self.assertRaisesRegex(ValueError, "architecture"):
            package.make_bundle(files, SOURCE, "amd64", "fixture")

    def test_downloaded_source_architecture_and_content_are_verified(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            package.inspect_bundle(self.bundle(), "b" * 40, "amd64")
        with self.assertRaises(ValueError):
            package.inspect_bundle(self.bundle(), SOURCE, "arm64")
        corrupted = rewrite_bundle(self.bundle(), lambda files: [(member, content + b"altered" if member.name.startswith("bin/") else content) for member, content in files])
        with self.assertRaisesRegex(ValueError, "content"):
            package.inspect_bundle(corrupted, SOURCE, "amd64")

    def test_qualification_claim_cannot_be_added(self):
        def change(files):
            for member, raw in files:
                if member.name == "manifest.json":
                    manifest = json.loads(raw)
                    manifest["native_runtime_qualification"] = True
                    raw = json.dumps(manifest).encode()
                yield member, raw
        with self.assertRaisesRegex(ValueError, "qualification"):
            package.inspect_bundle(rewrite_bundle(self.bundle(), change), SOURCE, "amd64")

    def test_traversal_symlinks_duplicates_and_extra_members_refused(self):
        for mutation in ("traversal", "symlink", "duplicate", "extra"):
            def change(files):
                if mutation == "traversal":
                    files[0][0].name = "../private"
                elif mutation == "symlink":
                    files[0][0].type = tarfile.SYMTYPE
                    files[0][0].linkname = "/outside"
                elif mutation == "duplicate":
                    files[-1][0].name = files[0][0].name
                else:
                    files.append((tarfile.TarInfo("private.key"), b"inert fixture"))
                return files
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                package.inspect_bundle(rewrite_bundle(self.bundle(), change), SOURCE, "amd64")

    def test_external_checksum_and_exact_public_inventory_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for arch in package.ARCHITECTURES:
                parent = root / arch
                parent.mkdir()
                name = f"tunnex-sandbox-linux-{arch}.tar.gz"
                raw = self.bundle(arch)
                (parent / name).write_bytes(raw)
                (parent / (name + ".sha256")).write_text(f"{package.digest(raw)}  {name}\n")
            package.verify_directory(root, SOURCE)
            extra = root / "raw-operation-log.json"
            extra.write_text("inert fixture")
            with self.assertRaisesRegex(ValueError, "inventory"):
                package.verify_directory(root, SOURCE)
            extra.unlink()
            (root / "amd64/tunnex-sandbox-linux-amd64.tar.gz.sha256").write_text("0" * 64)
            with self.assertRaisesRegex(ValueError, "checksum"):
                package.verify_directory(root, SOURCE)

    def test_portable_installer_accepts_actual_package_format_and_refuses_arm64_activation(self):
        spec = importlib.util.spec_from_file_location("portable_sandbox_install", package.ROOT / "deploy/sandbox/install/install.py")
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        self.assertEqual(set(package.ASSETS), installer.ASSETS)
        self.assertEqual(package.API_COMMANDS, installer.COMMANDS)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "public.tar.gz"
            for arch in package.ARCHITECTURES:
                raw = self.bundle(arch)
                path.write_bytes(raw)
                cfg = {"source_sha": SOURCE, "bundle": {"path": str(path), "sha256": package.digest(raw)}}
                if arch == "amd64":
                    accepted = installer.bundle_payload(cfg)
                    self.assertEqual(set(accepted), set(package.binary_names(arch)) | set(package.ASSETS) | {"manifest.json", "SHA256SUMS"})
                else:
                    with self.assertRaises(ValueError):
                        installer.bundle_payload(cfg)

    def test_build_uses_only_committed_source_and_readonly_cross_compile(self):
        for arch in package.ARCHITECTURES:
            calls = []
            source = io.BytesIO()
            with tarfile.open(fileobj=source, mode="w") as archive:
                for module in ("api", "node", "cli"):
                    member = tarfile.TarInfo(f"apps/{module}/go.mod")
                    raw = b"module public-fixture\n"
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))

            def fake_run(args, *, cwd=package.ROOT, env=None):
                calls.append((args, cwd, env))
                if args[:3] == ["git", "rev-parse", "HEAD"]:
                    return SOURCE.encode()
                if args[:2] == ["git", "diff"]:
                    return b""
                if args[:2] == ["go", "version"]:
                    return b"go version go1.26.8 linux/amd64\n"
                if args[:2] == ["git", "archive"]:
                    return source.getvalue()
                if args[:2] == ["git", "show"]:
                    return b"public fixture recipe\n"
                self.assertEqual(args[:2], ["go", "build"])
                self.assertNotEqual(cwd, package.ROOT / "apps/api")
                self.assertEqual(env["GOFLAGS"], "-mod=readonly")
                self.assertEqual(env["GOOS"], "linux")
                self.assertEqual(env["GOARCH"], arch)
                self.assertEqual(env["CGO_ENABLED"], "0")
                self.assertEqual(env["GOWORK"], "off")
                self.assertIn("-buildvcs=false", args)
                if "-o" in args:
                    Path(args[args.index("-o") + 1]).write_bytes(elf(arch))
                else:
                    self.assertEqual(arch, "arm64")
                    self.assertEqual(args[-1], "./...")
                return b""

            with tempfile.TemporaryDirectory() as temporary, patch.object(package, "run", side_effect=fake_run):
                output = Path(temporary).resolve() / arch
                package.build(arch, output)
                raw = (output / f"tunnex-sandbox-linux-{arch}.tar.gz").read_bytes()
                package.inspect_bundle(raw, SOURCE, arch)
            builds = [args for args, _, _ in calls if args[:2] == ["go", "build"]]
            self.assertEqual(len(builds), 10 if arch == "arm64" else 8)
            self.assertEqual(sum("enterprise" in args for args in builds), 4 if arch == "arm64" else 3)


if __name__ == "__main__":
    unittest.main()
