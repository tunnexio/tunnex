#!/usr/bin/env python3
"""Normal API enrollment for the explicitly owned localhost Azure lab only."""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import urllib.error
import urllib.request

API = "http://127.0.0.1:48083"
NODE_NAME = "azure-local-native-gateway"
SITE_NAME = "Azure local qualification site"
LOCAL_PREFIX = "10.241.10.0/24"

class LabError(Exception):
    def __init__(self,message,status=None):
        super().__init__(message)
        self.status=status

class Client:
    def __init__(self, account):
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.call("POST", "/api/v1/auth/login", account)
        self.call("GET", "/api/v1/auth/me")

    def call(self, method, path, data=None, headers=None):
        request = urllib.request.Request(API + path, data=None if data is None else json.dumps(data).encode(), method=method,
            headers={"Content-Type": "application/json", "Origin": API, "X-Tunnex-CSRF": "1", **(headers or {})})
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(1 << 20)
                return None if not raw else json.loads(raw)
        except urllib.error.HTTPError as error:
            # Never surface response bodies, cookies, request payloads or keys.
            code = "unavailable"
            try:
                body = json.loads(error.read(1 << 16))
                if isinstance(body, dict):
                    candidate = body.get("code", body.get("error", {}).get("code") if isinstance(body.get("error"), dict) else None)
                    if isinstance(candidate, str) and candidate.replace("_", "").isalnum():
                        code = candidate
            except (ValueError, TypeError):
                pass
            raise LabError(f"{method} {path}: HTTP {error.code}, code {code}", error.code) from None
        except (OSError, ValueError):
            raise LabError("Owned local API unavailable or invalid response") from None

def private_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise LabError("Refuse symlink private output")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(text)
    path.chmod(0o600)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "bind"))
    parser.add_argument("--private-root", type=Path, default=Path(__file__).resolve().parent / ".runtime")
    args = parser.parse_args()
    private = args.private_root.resolve()
    credentials = private / "ui-accounts.json"
    if not credentials.exists() or credentials.is_symlink() or credentials.stat().st_mode & 0o077:
        raise LabError("Private owner fixture missing or permissions exceed0600")
    accounts = json.loads(credentials.read_text())
    if accounts["owner"]["email"] != "browser-owner@azure-s2s.local":
        raise LabError("Refuse unrelated owner account")
    client = Client(accounts["owner"])
    organizations = client.call("GET", "/api/v1/organizations")
    owned = [org for org in organizations if org.get("slug") == "azure-s2s-local"]
    if len(owned) != 1:
        raise LabError("Owned Azure local organization is not unique")
    org = owned[0]["id"]
    prefix = f"/api/v1/organizations/{org}"
    state_path = private / "api-setup.json"
    nodes = [node for node in client.call("GET", prefix + "/nodes") if node.get("name") == NODE_NAME]
    if len(nodes) > 1:
        raise LabError("Owned gateway name is ambiguous; no changes made")
    sites = [site for site in client.call("GET", prefix + "/sites") if site.get("name") == SITE_NAME]
    if len(sites) > 1:
        raise LabError("Owned Site name is ambiguous; no changes made")
    site = sites[0] if sites else client.call("POST", prefix + "/sites", {"name": SITE_NAME})
    settings = client.call("GET", prefix + "/ipsec/settings")
    if not settings["enabled"]:
        client.call("PUT", prefix + "/ipsec/settings", {"enabled": True, "expected_revision": settings["revision"]})
    if args.phase == "prepare":
        token_path = private / "gateway.env"
        if not nodes and not token_path.exists():
            token = client.call("POST", prefix + "/nodes/join-token", {"node_name": NODE_NAME, "enrols_kind": "gateway"})["join_token"]
            if not isinstance(token, str) or "\n" in token or "\r" in token:
                raise LabError("Invalid enrollment token shape")
            private_write(token_path, "TUNNEX_JOIN_TOKEN=" + token + "\n")
        private_write(state_path, json.dumps({"org_id": org, "site_id": site["id"], "node_name": NODE_NAME, "local_prefix": LOCAL_PREFIX}, indent=2))
        print("Owned Site and IPsec opt-in prepared through normal API; join token stays private. Start the real native gateway, then run bind.")
        return
    if not nodes or nodes[0].get("status") != "active":
        raise LabError("Real gateway is not enrolled and active; no capability or health will be fabricated")
    node = nodes[0]
    client.call("POST", prefix + f"/sites/{site['id']}/bind", {"node_id": node["id"]})
    subnets = client.call("GET", prefix + f"/sites/{site['id']}/subnets")
    subnet = next((item for item in subnets if item.get("cidr") == LOCAL_PREFIX), None)
    if subnet is None:
        subnet = client.call("POST", prefix + f"/sites/{site['id']}/subnets", {"cidr": LOCAL_PREFIX})
    if subnet.get("status") != "approved":
        client.call("POST", prefix + f"/site-subnets/{subnet['id']}/approve", {})
    private_write(state_path, json.dumps({"org_id": org, "site_id": site["id"], "gateway_id": node["id"], "node_name": NODE_NAME, "local_prefix": LOCAL_PREFIX}, indent=2))
    print("Real owned gateway bound and local prefix approved through normal API; no capability or SA/BGP status seeded.")

if __name__ == "__main__":
    try:
        main()
    except (LabError, KeyError, ValueError):
        import sys
        error = sys.exc_info()[1]
        print(str(error) if isinstance(error, LabError) else "Invalid private input or owned lab API shape", file=sys.stderr)
        raise SystemExit(1)
