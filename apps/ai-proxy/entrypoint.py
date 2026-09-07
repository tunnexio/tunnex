"""Load private file secrets, then invoke the unmodified LiteLLM OSS proxy.

This module does not read secrets or contact a database when imported.
"""

import os
from pathlib import Path
import sys
from urllib.parse import quote


SECRET_FILES = {
    "master": "/run/secrets/ai_proxy_master_key",
    "salt": "/run/secrets/ai_proxy_salt_key",
    "database": "/run/secrets/ai_proxy_database_password",
}


def read_secret(path: str) -> str:
    value = Path(path).read_text(encoding="utf-8").rstrip("\r\n")
    if not 32 <= len(value) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("invalid private secret file")
    return value


def runtime_environment(paths: dict[str, str] = SECRET_FILES) -> dict[str, str]:
    secrets = {name: read_secret(path) for name, path in paths.items()}
    if len(set(secrets.values())) != len(secrets):
        raise ValueError("master, salt and database secrets must be independent")
    if not secrets["master"].startswith("sk-"):
        raise ValueError("master secret must start with sk-")
    # No caller-supplied DSN: this package can only address its separate database.
    database_url = (
        "postgresql://litellm:"
        + quote(secrets["database"], safe="")
        + "@ai-proxy-postgres:5432/litellm"
    )
    return {
        "LITELLM_MASTER_KEY": secrets["master"],
        "LITELLM_SALT_KEY": secrets["salt"],
        "DATABASE_URL": database_url,
    }


def main() -> int:
    if len(sys.argv) != 1:
        print("ai-proxy accepts no startup overrides", file=sys.stderr)
        return 2
    try:
        env = dict(os.environ)
        env.update(runtime_environment())
    except (OSError, UnicodeError, ValueError):
        # Do not print paths, values, DSNs or upstream exception text.
        print("ai-proxy: missing or invalid independent private secret files", file=sys.stderr)
        return 2
    # Normal startup is schema-read-only. Explicit schema provisioning is a
    # separate installation action, not an automatic migration/recovery path.
    env.update({"DISABLE_SCHEMA_UPDATE": "true", "DISABLE_ADMIN_UI": "true"})
    os.execvpe("litellm", [
        "litellm", "--config", "/app/config.yaml", "--host", "0.0.0.0",
        "--port", "4000", "--num_workers", "1",
    ], env)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

