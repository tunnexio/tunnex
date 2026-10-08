"""Prepare private, persistent credentials for the optional local UI fixture."""
from pathlib import Path
import os
import secrets
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
ENV = ROOT / ".env"


def read_env():
    lines = ENV.read_text().splitlines() if ENV.exists() else []
    values = {}
    for line in lines:
        clean = line.strip()
        if not clean or clean.startswith("#") or "=" not in clean:
            continue
        key, value = clean.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return lines, values


def main():
    lines, values = read_env()
    target = "http://bifrost:8080"
    if values.get("TUNNEX_AI_GATEWAY_URL") not in (None, "", target):
        raise SystemExit("An existing AI Gateway is configured; local fixture setup did not change it.")
    user = values.get("TUNNEX_AI_GATEWAY_ADMIN_USER", "")
    password = values.get("TUNNEX_AI_GATEWAY_ADMIN_PASSWORD", "")
    if bool(user) != bool(password):
        raise SystemExit("The existing AI admin credential is incomplete; local fixture setup did not change it.")
    private_keys = ["TUNNEX_AI_GATEWAY_ADMIN_PASSWORD", "TUNNEX_DEV_AI_FIXTURE_ENCRYPTION_KEY", "TUNNEX_DEV_AI_FIXTURE_PROVIDER_KEY"]
    if any(not values.get(key) for key in private_keys):
        result = subprocess.run(["docker", "volume", "ls", "--filter", "label=com.docker.compose.volume=ai_ui_fixture_config", "--format", "{{.Name}}"], capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit("Could not check existing local AI state. Ensure Docker is available before generating credentials.")
        if result.stdout.strip():
            raise SystemExit("Local AI state already exists but matching credentials are missing. Restore its private .env; no credentials were replaced.")
    updates = {
        "TUNNEX_AI_GATEWAY_URL": target,
        "TUNNEX_AI_GATEWAY_ADMIN_USER": user or "local-fixture-admin",
        "TUNNEX_AI_GATEWAY_ADMIN_PASSWORD": password or secrets.token_hex(32),
        "TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED": "true",
        "TUNNEX_AI_BOOTSTRAP_VERSION": "local-ui-fixture",
        "TUNNEX_DEV_AI_FIXTURE_ENCRYPTION_KEY": values.get("TUNNEX_DEV_AI_FIXTURE_ENCRYPTION_KEY") or secrets.token_hex(32),
        "TUNNEX_DEV_AI_FIXTURE_PROVIDER_KEY": values.get("TUNNEX_DEV_AI_FIXTURE_PROVIDER_KEY") or secrets.token_hex(32),
    }
    seen = set()
    result = []
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else ""
        if key in updates:
            if key in private_keys + ["TUNNEX_AI_GATEWAY_ADMIN_USER"] and values.get(key):
                result.append(line)  # Preserve the existing literal quoting/escaping.
                seen.add(key)
            elif key not in seen:
                result.append(key + "=" + updates[key])
                seen.add(key)
        else:
            result.append(line)
    result.extend(key + "=" + value for key, value in updates.items() if key not in seen)
    descriptor, name = tempfile.mkstemp(prefix=".env.local-ai-", dir=ROOT)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as output:
            output.write("\n".join(result) + "\n")
        os.replace(name, ENV)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    print("Local AI fixture profile prepared. Existing settings preserved; credentials remain in private .env.")


if __name__ == "__main__":
    main()
