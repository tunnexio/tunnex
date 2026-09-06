#!/usr/bin/env python3
"""Exercise the unmodified chart's Helm lookup against a read-only API fixture.

Unlike offline `helm template`, --dry-run=server executes the real lookup.
This is a template/lookup contract, not a Kubernetes installation or race test.
"""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


CHART = Path(__file__).resolve().parent / "helm" / "tunnex-gateway"
ORG = "11111111-1111-4111-8111-111111111111"
CLAIM = "22222222-2222-4222-8222-222222222222"
ORG_KEY = "tunnex.io/organization-id"
CLAIM_KEY = "tunnex.io/lifecycle-claim"
PVC_PATH = "/api/v1/namespaces/tunnex-system/persistentvolumeclaims/gw-lookup-tunnex-gateway-state"


class API(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        self.server.requests.append(("GET", path))
        if path == "/version":
            self.respond(200, {"major": "1", "minor": "31", "gitVersion": "v1.31.0"})
        elif path == "/api":
            self.respond(200, {"kind": "APIVersions", "apiVersion": "v1", "versions": ["v1"]})
        elif path == "/apis":
            self.respond(200, {"kind": "APIGroupList", "apiVersion": "v1", "groups": []})
        elif path == "/api/v1":
            self.respond(200, {"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": "v1", "resources": [
                {"name": "persistentvolumeclaims", "singularName": "persistentvolumeclaim", "namespaced": True,
                 "kind": "PersistentVolumeClaim", "verbs": ["get"]}
            ]})
        elif path == PVC_PATH:
            if self.server.failure:
                self.respond(self.server.failure, {"kind": "Status", "apiVersion": "v1", "status": "Failure",
                                                  "reason": "Forbidden" if self.server.failure == 403 else "InternalError",
                                                  "message": "fixture lookup refused", "code": self.server.failure})
            elif self.server.pvc is None:
                self.respond(404, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404})
            else:
                self.respond(200, self.server.pvc)
        else:
            self.respond(404, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404})

    def refuse_mutation(self):
        self.server.requests.append((self.command, urlsplit(self.path).path))
        self.respond(405, {"kind": "Status", "status": "Failure", "code": 405})

    do_POST = do_PUT = do_PATCH = do_DELETE = refuse_mutation


class RetainedPVCLookup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helm = shutil.which("helm")
        if not cls.helm:
            raise RuntimeError("helm is required for live PVC lookup contract")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), API)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.tmp = tempfile.TemporaryDirectory(prefix="tunnex-pvc-lookup-")
        cls.config = Path(cls.tmp.name) / "kubeconfig.json"
        cls.config.write_text(json.dumps({"apiVersion": "v1", "kind": "Config",
            "clusters": [{"name": "fixture", "cluster": {"server": f"http://127.0.0.1:{cls.server.server_port}"}}],
            "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}],
            "users": [{"name": "fixture", "user": {}}], "current-context": "fixture"}))
        cls.config.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.tmp.cleanup()

    def render(self, annotations=None, *, absent=False, reuse=False, failure=0, overrides=None, upgrade=False):
        self.server.pvc = None if absent else {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {
            "name": "gw-lookup-tunnex-gateway-state", "namespace": "tunnex-system", "uid": "unchanged-fixture-identity",
            "resourceVersion": "7", "annotations": annotations or {}}, "spec": {"volumeName": "unchanged-volume"}}
        before = copy.deepcopy(self.server.pvc)
        self.server.failure = failure
        self.server.requests = []
        values = {"acknowledgePrivileged": "true", "controlPlane.apiURL": "https://cp.example.test/api",
                  "controlPlane.agentURL": "https://cp.example.test:8443", "enrollment.mode": "reuse" if reuse else "enroll"}
        if reuse:
            values["persistence.existingClaim"] = "gw-lookup-tunnex-gateway-state"
        else:
            values.update({"nodeName": "lookup-fixture", "enrollment.existingSecret": "fixture-external-secret",
                           "persistence.provenance.organizationID": ORG, "persistence.provenance.lifecycleClaim": CLAIM})
        values.update(overrides or {})
        cmd = [self.helm, "template", "gw-lookup", str(CHART), "--namespace", "tunnex-system",
               "--kubeconfig", str(self.config), "--dry-run=server"]
        if upgrade:
            cmd.append("--is-upgrade")
        for key, value in values.items():
            cmd.extend(["--set" if key == "acknowledgePrivileged" else "--set-string", f"{key}={value}"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env={**os.environ, "NO_PROXY": "127.0.0.1"})
        self.assertEqual(before, self.server.pvc, "fixture identity/provenance changed")
        self.assertTrue(all(method == "GET" for method, _ in self.server.requests), self.server.requests)
        return result

    def assert_lookup(self):
        self.assertIn(("GET", PVC_PATH), self.server.requests, "the real Helm lookup did not execute")

    def test_absent_and_matching_enrollment(self):
        for upgrade in (False, True):
            for absent in (False, True):
                with self.subTest(upgrade=upgrade, absent=absent):
                    r = self.render({ORG_KEY: ORG, CLAIM_KEY: CLAIM}, absent=absent, upgrade=upgrade)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assert_lookup()
                    self.assertIn("kind: PersistentVolumeClaim", r.stdout)
                    self.assertIn(f'{ORG_KEY}: "{ORG}"', r.stdout)
                    self.assertIn(f'{CLAIM_KEY}: "{CLAIM}"', r.stdout)

    def test_existing_unproved_enrollment_refuses(self):
        cases = {"missing": {}, "only-org": {ORG_KEY: ORG}, "only-claim": {CLAIM_KEY: CLAIM},
                 "malformed-org": {ORG_KEY: "not-a-uuid", CLAIM_KEY: CLAIM},
                 "malformed-claim": {ORG_KEY: ORG, CLAIM_KEY: "not-a-uuid"},
                 "nil-org": {ORG_KEY: "00000000-0000-0000-0000-000000000000", CLAIM_KEY: CLAIM},
                 "nil-claim": {ORG_KEY: ORG, CLAIM_KEY: "00000000-0000-0000-0000-000000000000"},
                 "cross-org": {ORG_KEY: "33333333-3333-4333-8333-333333333333", CLAIM_KEY: CLAIM},
                 "cross-claim": {ORG_KEY: ORG, CLAIM_KEY: "33333333-3333-4333-8333-333333333333"},
                 "uppercase": {ORG_KEY: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", CLAIM_KEY: CLAIM}}
        for name, annotations in cases.items():
            for upgrade in (False, True):
                with self.subTest(case=name, upgrade=upgrade):
                    r = self.render(annotations, upgrade=upgrade)
                    self.assertNotEqual(r.returncode, 0, r.stdout)
                    self.assert_lookup()
                    self.assertIn("retained PVC", r.stderr)
                    self.assertNotIn("kind: PersistentVolumeClaim", r.stdout)

    def test_api_errors_fail_closed(self):
        for status in (403, 500):
            with self.subTest(status=status):
                r = self.render({ORG_KEY: ORG, CLAIM_KEY: CLAIM}, failure=status)
                self.assertNotEqual(r.returncode, 0)
                self.assert_lookup()
                self.assertIn("fixture lookup refused", r.stderr)
                self.assertNotIn("kind: PersistentVolumeClaim", r.stdout)

    def test_existing_claim_requires_supplied_provenance(self):
        # Legacy fresh enrollment remains compatible, but cannot claim a disk
        # already bearing lifecycle identity without presenting the same pair.
        r = self.render({ORG_KEY: ORG, CLAIM_KEY: CLAIM}, overrides={
            "persistence.provenance.organizationID": "", "persistence.provenance.lifecycleClaim": ""})
        self.assertNotEqual(r.returncode, 0)
        self.assert_lookup()
        self.assertIn("retained PVC", r.stderr)

    def test_invalid_supplied_provenance_refuses_even_fresh(self):
        for field in ("organizationID", "lifecycleClaim"):
            for value in ("", "not-a-uuid", "00000000-0000-0000-0000-000000000000",
                          "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"):
                with self.subTest(field=field, value=value):
                    r = self.render(absent=True, overrides={f"persistence.provenance.{field}": value})
                    self.assertNotEqual(r.returncode, 0)
                    self.assertRegex(r.stderr, "provenance|organizationID|lifecycleClaim")
                    self.assertNotIn("kind: PersistentVolumeClaim", r.stdout)

    def test_legacy_tokenless_reuse_does_not_relabel_or_enroll(self):
        r = self.render({}, reuse=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("kind: PersistentVolumeClaim", r.stdout)
        self.assertNotIn("TUNNEX_JOIN_TOKEN", r.stdout)
        self.assertNotIn("kind: Secret", r.stdout)
        self.assertIn("claimName: gw-lookup-tunnex-gateway-state", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
