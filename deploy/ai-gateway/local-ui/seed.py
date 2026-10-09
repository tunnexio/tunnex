"""Seed only the demo org through the real private-engine API. Never call an external provider."""
import argparse
import http.cookiejar
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from prepare import read_env

ORG = "01900000-0000-7000-8000-000000000001"
GROUP = "01900000-0000-7000-8000-0000000a00f1"
MODELS = ["openrouter/local-fixture-chat", "openrouter/local-fixture-code", "openrouter/local-fixture-embedding"]
NAME = "Local fixture · simulated models"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, method, path, body=None, stream=False):
        headers = {"X-Tunnex-CSRF": "local-ai-fixture"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read()
                if stream:
                    return raw.decode()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            try:
                code = json.loads(error.read()).get("error", {}).get("code", "")
            except (ValueError, AttributeError):
                code = ""
            # Never print raw upstream bodies, credentials or cookies.
            raise RuntimeError(f"{method} {path.split('?')[0]}: HTTP {error.code} {code}") from None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://localhost")
    parser.add_argument("--requests", type=int, default=12)
    args = parser.parse_args()
    if not 0 <= args.requests <= 25:
        raise SystemExit("Fixture request count must be between zero and 25")
    base = urllib.parse.urlparse(args.base)
    if base.scheme != "http" or base.hostname not in ("localhost", "127.0.0.1", "::1", "api", "host.docker.internal") or base.username or base.password or base.path not in ("", "/") or base.query or base.fragment:
        raise SystemExit("This fixture helper requires the existing local HTTP development API")
    _, env = read_env()
    if env.get("TUNNEX_AI_GATEWAY_URL") != "http://bifrost:8080" or not env.get("TUNNEX_DEV_AI_FIXTURE_PROVIDER_KEY"):
        raise SystemExit("Prepare the private local fixture profile first")
    client = Client(args.base)
    client.request("GET", "/api/v1/meta")
    client.request("POST", "/api/v1/auth/login", {"email": "owner@demo.tunnex.local", "password": "tunnex-demo-password"})
    organizations = client.request("GET", "/api/v1/organizations")
    if not any(org.get("id") == ORG and org.get("slug") == "demo" and org.get("name") == "Demo Organization" for org in organizations):
        raise SystemExit("The expected local demo organization is missing")
    prefix = "/api/v1/organizations/" + ORG + "/ai-gateway"
    settings = client.request("GET", prefix)
    if not settings.get("available"):
        raise SystemExit("Local AI runtime is unavailable; no fixtures were changed")
    if not settings.get("enabled"):
        settings = client.request("PUT", prefix, {"enabled": True})
    providers = client.request("GET", prefix + "/providers")
    if not providers.get("management_available"):
        raise SystemExit("Local provider management is unavailable")
    matches = [item for item in providers["items"] if item["name"] == NAME]
    if len(matches) > 1:
        raise SystemExit("Ambiguous local fixture provider; no provider was changed")
    provider = matches[0] if matches else client.request("POST", prefix + "/providers", {
        "provider": "openrouter", "name": NAME, "models": MODELS,
        "model_modes": {MODELS[0]: "chat", MODELS[1]: "chat", MODELS[2]: "embedding"},
        "enabled": True, "api_key": env["TUNNEX_DEV_AI_FIXTURE_PROVIDER_KEY"],
    })
    if provider.get("models") != MODELS or not provider.get("enabled"):
        raise SystemExit("Existing local fixture provider was changed by a reviewer; it was preserved")
    if provider["status"] != "applied":
        raise SystemExit("Local fixture provider is not applied; inspect its actual synchronization error")
    if not any(item["name"] == "Local fixture · paused" for item in providers["items"]):
        client.request("POST", prefix + "/providers", {
            "provider": "openrouter", "name": "Local fixture · paused", "models": [MODELS[0]],
            "enabled": False, "api_key": env["TUNNEX_DEV_AI_FIXTURE_PROVIDER_KEY"],
        })
    checked = client.request("POST", prefix + "/providers/" + provider["id"] + "/test", {"expected_revision": provider["revision"]})
    catalog = client.request("GET", prefix + "/models?provider=openrouter&query=local-fixture&limit=20&offset=0")
    if not set(MODELS).issubset(item["id"] for item in catalog["items"]):
        raise SystemExit("The actual local fixture model catalog is incomplete")
    if args.requests:
        probe = client.request("POST", prefix + "/providers/test-connection", {
            "provider": "openrouter", "connection_id": provider["id"], "expected_revision": provider["revision"], "model": MODELS[0], "mode": "chat",
        })
        if probe["status"] != "success":
            raise SystemExit("The actual saved local fixture inference test failed")
    groups = client.request("GET", prefix + "/user-groups")
    if not any(group.get("id") == GROUP and group.get("name") == "AI fixture reviewers" for group in groups):
        raise SystemExit("Load the demo-only fixtures.sql group before granting models")
    grants = client.request("GET", prefix + "/user-model-grants")
    for model in MODELS:
        existing = next((grant for grant in grants if grant.get("group_id") == GROUP and grant.get("connection_id") == provider["id"] and grant.get("model") == model), None)
        if existing and existing.get("status") == "applied" and existing.get("enabled"):
            continue
        if existing:
            raise SystemExit("A reviewer changed a fixture grant; it was preserved")
        grant = client.request("POST", prefix + "/user-model-grants", {
            "group_id": GROUP, "connection_id": provider["id"], "model": model,
            "enabled": True, "expected_revision": 0,
        })
        if grant.get("status") != "applied":
            raise SystemExit("Local fixture grant is not applied; no access was claimed")
    workloads = client.request("GET", prefix + "/workloads")
    for name, enabled in [("Local fixture · support assistant", True), ("Local fixture · paused service", False)]:
        if any(item["name"] == name for item in workloads):
            continue  # Preserve subsequent reviewer changes; never mint enrollment keys automatically.
        created = client.request("POST", prefix + "/workloads", {
            "name": name, "enabled": enabled, "models": [{"connection_id": provider["id"], "model": model, "mode": "embedding" if model == MODELS[2] else "chat"} for model in MODELS],
            "daily_usd_threshold": None, "expected_revision": 0,
        })
        if enabled and created["status"] != "applied":
            raise SystemExit("Local fixture workload policy is not applied; no instance readiness was claimed")
    accessible = client.request("GET", prefix + "/my-models")
    if not set(MODELS).issubset(item["model"] for item in accessible):
        raise SystemExit("Actual demo member model access is incomplete")
    member = Client(args.base)
    member.request("POST", "/api/v1/auth/login", {"email": "member@demo.tunnex.local", "password": "tunnex-demo-password"})
    member_models = member.request("GET", prefix + "/my-models")
    if not set(MODELS).issubset(item["model"] for item in member_models):
        raise SystemExit("Actual demo member model access is incomplete")
    try:
        member.request("POST", prefix + "/inference/v1/chat/completions", {
            "model": "openrouter/local-fixture-denied", "messages": [{"role": "user", "content": "Local denied-model guard check."}],
        })
    except RuntimeError as error:
        if "HTTP 403 " not in str(error):
            raise
    else:
        raise SystemExit("The local denied-model guard did not refuse access")
    baseline = client.request("GET", prefix + "/usage?dashboard=true")["total_requests"]
    for index in range(args.requests):
        streamed = index == args.requests - 1
        caller = member if index % 2 == 0 else client
        result = caller.request("POST", prefix + "/inference/v1/chat/completions", {
            "model": MODELS[index % 2], "messages": [{"role": "user", "content": "Local UI fixture: return a simulated response."}],
            "max_tokens": 64, "stream": streamed,
        }, stream=streamed)
        if streamed:
            if "[DONE]" not in result or "Local fixture response" not in result:
                raise SystemExit("Actual local streaming verification failed")
        elif "Local fixture response" not in result["choices"][0]["message"]["content"]:
            raise SystemExit("Actual local inference verification failed")
    if args.requests:
        embedding = client.request("POST", prefix + "/inference/v1/embeddings", {"model": MODELS[2], "input": "Local UI fixture"})
        if len(embedding["data"][0]["embedding"]) != 4:
            raise SystemExit("Actual local embedding verification failed")
    # The native ledger writes asynchronously. Verify actual observation rather
    # than asserting a count or directly inserting accounting rows.
    expected = baseline + args.requests + (1 if args.requests else 0)
    deadline = time.monotonic() + 20
    while True:
        usage = client.request("GET", prefix + "/usage?dashboard=true")
        if usage["total_requests"] >= expected:
            break
        if time.monotonic() >= deadline:
            raise SystemExit("Local inference succeeded, but its native accounting has not converged")
        time.sleep(0.5)
    final_providers = client.request("GET", prefix + "/providers")
    final_grants = client.request("GET", prefix + "/user-model-grants")
    final_workloads = client.request("GET", prefix + "/workloads")
    print(json.dumps({
        "fixture": True, "external_requests": False, "available": settings["available"], "enabled": settings["enabled"],
        "providers": [{"name": item["name"], "status": item["status"], "models": item["models"], "last_test_status": item["last_test_status"]} for item in final_providers["items"]],
        "applied_fixture_grants": len([item for item in final_grants if item.get("group_id") == GROUP and item.get("status") == "applied"]),
        "fixture_workloads": [{"name": item["name"], "enabled": item["enabled"], "status": item["status"]} for item in final_workloads if item["name"].startswith("Local fixture · ")],
        "accessible_models": [item["model"] for item in accessible],
        "member_models": [item["model"] for item in member_models], "denied_model_guard": "HTTP 403",
        "vpn_unavailable_reasons": sorted({item["vpn_unavailable_reason"] for item in accessible if item.get("vpn_unavailable_reason")}),
        "observed_requests": usage["total_requests"], "observed_tokens": usage["total_tokens"],
        "uncosted_requests": usage["uncosted_requests"], "catalog_check": checked["last_test_status"],
    }))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
