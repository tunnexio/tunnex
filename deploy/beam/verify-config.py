#!/usr/bin/env python3
"""Check rendered opt-in wiring without starting services or printing secrets."""
import ipaddress
import json
import re
import sys
from pathlib import PurePosixPath
from urllib.parse import urlsplit


def verify(config):
    services = config.get("services", {})
    proxy = services.get("beam-proxy", {})
    api = services.get("api", {})
    init = services.get("beam-restore-init", {})
    if "beam" not in proxy.get("profiles", []) or "beam" not in init.get("profiles", []):
        raise ValueError("Beam must use the explicit beam profile")
    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", proxy.get("image", "")):
        raise ValueError("Beam proxy image must use an immutable sha256 digest")
    if init.get("image") != proxy["image"]:
        raise ValueError("Restore initialization must use the same verified image")
    if not proxy.get("read_only") or proxy.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in proxy.get("security_opt", []):
        raise ValueError("Beam proxy confinement is missing")
    ports = proxy.get("ports", [])
    if len(ports) != 2 or {p.get("target") for p in ports} != {8443, 8444}:
        raise ValueError("Publish only browser and connector TLS listeners")
    addresses = []
    for port in ports:
        if str(port.get("published")) != "443" or port.get("protocol", "tcp") != "tcp":
            raise ValueError("Both supported external TLS listeners must use TCP 443")
        try:
            address = ipaddress.ip_address(port.get("host_ip", ""))
        except ValueError:
            raise ValueError("Choose explicit listener bind IP addresses") from None
        if address.is_unspecified or address.version != 4:
            raise ValueError("This override requires explicit IPv4 bind addresses")
        addresses.append(address)
    if len(set(addresses)) != 2:
        raise ValueError("Browser and connector TCP 443 need distinct bind IP addresses")
    for port in api.get("ports", []):
        if port.get("target") == 8445:
            raise ValueError("Control-plane Beam authority must remain internal")
    environment = api.get("environment", {})
    for key in ("APP_BASE_URL", "TUNNEX_BEAM_PROXY_URL"):
        url = urlsplit(environment.get(key, ""))
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValueError("Console and connector must have fixed HTTPS base URLs")
    if environment.get("TUNNEX_BEAM_DOMAIN_READY") not in ("true", "false"):
        raise ValueError("Installation readiness must be explicitly true or false")
    for service in (api, proxy):
        mounts = {v.get("target"): v for v in service.get("volumes", [])}
        restore = mounts.get("/var/lib/tunnex/app-restore", {})
        if restore.get("type") != "volume" or restore.get("source") != "app_restore" or not restore.get("read_only"):
            raise ValueError("Serving processes need the independent restore volume read-only")
    mounts = {v.get("target"): v for v in proxy.get("volumes", [])}
    secrets = mounts.get("/etc/tunnex/beam", {})
    if secrets.get("type") != "bind" or not PurePosixPath(secrets.get("source", "")).is_absolute() or not secrets.get("read_only"):
        raise ValueError("Beam credentials must use a fixed read-only private directory")
    if init.get("network_mode") != "none":
        raise ValueError("Restore initialization must have no network")


def main():
    try:
        verify(json.load(sys.stdin))
    except (ValueError, TypeError, KeyError, AttributeError):
        # Never echo rendered configuration: it can contain database credentials.
        print("Beam wiring check failed; review the fixed URLs, image digest, distinct bind IPs, private mounts and listener confinement.", file=sys.stderr)
        return 1
    print("Beam opt-in wiring checked. Public DNS/TLS and image provenance require separate qualification.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
