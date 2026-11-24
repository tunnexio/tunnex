#!/usr/bin/env python3
"""tunnex-app-access: host-side App Access operations (AA-EN-1, Phase 1a).

  adopt  Convert a hand-written App Access composition (for example the demo's
         tunnex.yml + app-access.yml + app-access-demo.yml) into the managed
         composition that upgrade.sh admits. Dry run by default.
  renew  Validate a renewed public certificate/key pair and install it into the
         proxy secrets directory, then restart the proxy in a controlled way.
         Dry run by default.

Standard library only. Never prints, logs or stores secret material: container
environment is never inspected, private keys are only handed to the local TLS
library, and only names, paths, fingerprints and dates are shown.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import ssl
import subprocess
import sys
import time

MARKER = "/var/lib/tunnex/app-restore"
SECRETS_TARGET = "/etc/tunnex/app-proxy"
PROXY_UID = 10001
DEFAULT_EDGE_HTTPS_PUBLISH = "127.0.0.1:8446"
ADOPTED_FILES = "TUNNEX_APP_ACCESS_ADOPTED_CONFIG_FILES"
ADOPTED_HASHES = "TUNNEX_APP_ACCESS_ADOPTED_OVERLAYS_SHA256"
CONSOLE_KEYS = (
    "TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL",
    "TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_SERVER_NAME",
    "TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_CA_FILE",
)
HERE = pathlib.Path(__file__).resolve().parent


class Refused(Exception):
    """A safety refusal. Unless changed=True, nothing was changed."""

    def __init__(self, message, changed=False):
        super().__init__(message)
        self.changed = changed


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# .env: read and rewrite as data, never as shell.
def read_env(path):
    values = {}
    for line in pathlib.Path(path).read_text().splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values.setdefault(key, value)
    return values


def write_env(path, updates):
    path = pathlib.Path(path)
    for key, value in updates.items():
        if "\n" in value or "\r" in value:
            raise Refused("refusing a multi-line .env value for %s" % key)
    lines, seen = [], set()
    for line in path.read_text().splitlines():
        key = line.split("=", 1)[0] if "=" in line and not line.lstrip().startswith("#") else None
        if key in updates:
            if key not in seen:
                lines.append("%s=%s" % (key, updates[key]))
                seen.add(key)
            continue
        lines.append(line)
    for key, value in updates.items():
        if key not in seen:
            lines.append("%s=%s" % (key, value))
    atomic_write(path, ("\n".join(lines) + "\n").encode(), os.stat(path).st_mode & 0o777)


def atomic_write(path, data, mode, uid=None, gid=None):
    path = pathlib.Path(path)
    tmp = path.with_name(path.name + ".next")
    if tmp.exists():
        tmp.unlink()
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if uid is not None:
            os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))
    dirfd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


# --------------------------------------------------------------------------
# Docker: labels, mounts and port bindings only; never container environment.
def docker(*args, input_bytes=None, env=None):
    result = subprocess.run(["docker", *args], input=input_bytes, capture_output=True, env=env)
    if result.returncode != 0:
        raise Refused("docker %s failed: %s" % (args[0], result.stderr.decode(errors="replace").strip()[:300]))
    return result.stdout.decode()


def participants(project):
    ids = docker("ps", "-a", "--filter", "label=com.docker.compose.project=%s" % project, "--format", "{{.ID}}").split()
    found = {"api": [], "app-proxy": []}
    for cid in ids:
        raw = docker("inspect", "--format", "{{json .Config.Labels}}|{{json .Mounts}}|{{json .HostConfig.PortBindings}}", cid).strip()
        labels, mounts, ports = (json.loads(part) for part in raw.split("|", 2))
        service = labels.get("com.docker.compose.service")
        if service not in found or labels.get("com.docker.compose.oneoff") == "True":
            continue
        found[service].append({
            "id": cid,
            "config_files": labels.get("com.docker.compose.project.config_files", ""),
            "working_dir": labels.get("com.docker.compose.project.working_dir", ""),
            "marker": [m.get("Name", "") for m in mounts or [] if m.get("Destination") == MARKER and m.get("Type") == "volume"],
            "secrets": [m.get("Source", "") for m in mounts or [] if m.get("Destination") == SECRETS_TARGET],
            "ports": ports or {},
        })
    return found


def single_port(ports, key):
    bindings = ports.get(key)
    if bindings is None:
        return None
    if len(bindings) != 1:
        raise Refused("the proxy publishes %s more than once; adopt supports one binding per listener" % key)
    b = bindings[0]
    if not b.get("HostIp"):
        raise Refused("the proxy publishes %s without an explicit address; publish it on an explicit IP first" % key)
    return b["HostIp"], b["HostPort"]


def compose_config(directory, project, env_file, files, profiles):
    args = ["compose", "--project-name", project, "--project-directory", str(directory), "--env-file", str(env_file)]
    for f in files:
        args += ["-f", str(f)]
    env = dict(os.environ, COMPOSE_PROFILES=profiles)
    return json.loads(docker(*args, "config", "--format", "json", env=env))


def diff_paths(a, b, prefix=""):
    """Return the paths where two rendered values differ (names only, never values)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for key in sorted(set(a) | set(b)):
            out += diff_paths(a.get(key), b.get(key), "%s.%s" % (prefix, key) if prefix else key)
        return out
    return [] if a == b else [prefix]


def https_ports(ports):
    return [p for p in ports or [] if str(p.get("target")) == "443"]


# --------------------------------------------------------------------------
def adopt(args):
    directory = pathlib.Path(args.directory).resolve()
    env_file, base = directory / ".env", directory / "tunnex.yml"
    managed_path = directory / "app-access.yml"
    overlay_source = pathlib.Path(args.overlay).resolve() if args.overlay else HERE / "compose.yml"
    target_base = pathlib.Path(args.target_compose).resolve() if args.target_compose else HERE.parent / "tunnex.yml"
    for path in (env_file, base, overlay_source):
        if not path.is_file():
            raise Refused("%s not found" % path)
    if not target_base.is_file() or "TUNNEX_EDGE_HTTPS_PUBLISH" not in target_base.read_text():
        raise Refused("this tool must come from a release whose tunnex.yml supports TUNNEX_EDGE_HTTPS_PUBLISH "
                      "(extract it from the verified target release, see the App Access README)")
    env = read_env(env_file)
    project = env.get("COMPOSE_PROJECT_NAME") or "tunnex"
    found = participants(project)
    if len(found["api"]) != 1 or len(found["app-proxy"]) != 1:
        raise Refused("adopt needs exactly one API and one proxy in project %s (found %d and %d)"
                      % (project, len(found["api"]), len(found["app-proxy"])))
    api, proxy = found["api"][0], found["app-proxy"][0]
    if api["config_files"] != proxy["config_files"]:
        raise Refused("the API and the proxy were created from different composition files")
    files = api["config_files"].split(",")
    managed_overlay = overlay_source.read_bytes()
    managed_sha = hashlib.sha256(managed_overlay).hexdigest()

    # Idempotence: already managed, or already adopted and waiting for the upgrade.
    if files == [str(base), str(managed_path)] and env.get("TUNNEX_APP_ACCESS_COMPOSE_SHA256"):
        print("App Access already runs from the managed composition; nothing to adopt.")
        return 0
    if env.get(ADOPTED_FILES) == api["config_files"] and managed_path.is_file() \
            and sha256_file(managed_path) == env.get("TUNNEX_APP_ACCESS_COMPOSE_SHA256"):
        print("This composition was already adopted; nothing to change. Next: run the upgrade")
        print("  %s/upgrade.sh            (dry run)\n  %s/upgrade.sh --apply" % (directory, directory))
        return 0

    # Identity: the same checks the upgrade makes, refused rather than fixed.
    if len(files) < 3 or files[0] != str(base) or files[1] != str(managed_path):
        raise Refused("unknown composition %s; adopt converts tunnex.yml + app-access.yml + hand-written overlays"
                      % api["config_files"])
    extras = [pathlib.Path(f) for f in files[2:]]
    for extra in extras:
        if not extra.is_absolute() or not extra.is_file() or extra.is_symlink():
            raise Refused("hand-written overlay %s is missing or not a regular file" % extra)
    volume = "%s_app_restore" % project
    for name, p in (("API", api), ("proxy", proxy)):
        if p["marker"] != [volume]:
            raise Refused("the %s does not mount the restore barrier volume %s; it was preserved, inspect it first" % (name, volume))
    secrets_dir = env.get("TUNNEX_APP_PROXY_SECRETS_DIR", "")
    if not secrets_dir or proxy["secrets"] != [secrets_dir]:
        raise Refused("the proxy credential directory differs from TUNNEX_APP_PROXY_SECRETS_DIR in .env")
    if not env.get("TUNNEX_APP_ACCESS_BASE_DOMAIN"):
        raise Refused("TUNNEX_APP_ACCESS_BASE_DOMAIN is not set in .env")
    if not (env.get("TUNNEX_APP_PROXY_IMAGE") or "").startswith("ghcr.io/tunnexio/tunnex-app-proxy@sha256:"):
        raise Refused("TUNNEX_APP_PROXY_IMAGE in .env is not a signed digest pin")
    extra_keys = set(proxy["ports"]) - {"8443/tcp", "8444/tcp"}
    if extra_keys:
        raise Refused("the proxy publishes unexpected ports: %s" % ", ".join(sorted(extra_keys)))
    public = single_port(proxy["ports"], "8443/tcp")
    if public is None:
        raise Refused("the proxy does not publish its public listener 8443")
    gateway = single_port(proxy["ports"], "8444/tcp")

    # Unknown drift: what the hand-written overlays change must be exactly the
    # demo shape (Caddy loses public 443; proxy ports and console upstream).
    profiles = (env.get("COMPOSE_PROFILES") or "bundled-db")
    if "app-access" not in profiles.split(","):
        profiles += ",app-access"
    with_extras = compose_config(directory, project, env_file, files, profiles)
    without = compose_config(directory, project, env_file, files[:2], profiles)
    unknown = []
    services = set(with_extras.get("services", {})) | set(without.get("services", {}))
    caddy_loses_https = False
    for service in sorted(services):
        a = without.get("services", {}).get(service, {})
        b = with_extras.get("services", {}).get(service, {})
        for path in diff_paths(a, b, service):
            if path == "caddy.ports":
                kept = [p for p in a.get("ports", []) if p not in https_ports(a.get("ports"))]
                if b.get("ports") == kept and https_ports(a.get("ports")):
                    caddy_loses_https = True
                    continue
            elif path == "app-proxy.ports":
                continue  # checked against the running bindings above
            elif path in ("app-proxy.environment." + k for k in CONSOLE_KEYS):
                continue
            unknown.append(path)
    for top in sorted(set(with_extras) | set(without)):
        if top not in ("services", "name") and with_extras.get(top) != without.get(top):
            unknown.append(top)
    if unknown:
        raise Refused("the hand-written overlays change more than adopt can carry over: %s. "
                      "Move those settings into .env or remove them, then run adopt again" % ", ".join(unknown))
    proxy_env = with_extras["services"]["app-proxy"].get("environment") or {}
    console = {k: proxy_env.get(k) or "" for k in CONSOLE_KEYS}
    if caddy_loses_https and not console["TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL"]:
        raise Refused("Caddy does not publish 443 but the proxy does not forward the console; "
                      "the console would be unreachable")

    updates = {
        "TUNNEX_APP_PROXY_BIND_IP": public[0],
        "TUNNEX_APP_PROXY_PUBLIC_PORT": public[1],
    }
    notes = []
    if gateway:
        updates["TUNNEX_APP_PROXY_GATEWAY_BIND_IP"], updates["TUNNEX_APP_PROXY_GATEWAY_PORT"] = gateway
        host = args.gateway_host
        if host is None and gateway[0] not in ("0.0.0.0", "::", "127.0.0.1", "::1"):
            host = gateway[0]
            notes.append("gateways that follow the control plane will dial %s:%s (the address the listener is published on); "
                         "override with --gateway-host or --gateway-host ''" % (host, gateway[1]))
        updates["TUNNEX_APP_PROXY_GATEWAY_HOST"] = host or ""
    else:
        # Keep today's exposure: the gateway listener was not published.
        updates["TUNNEX_APP_PROXY_GATEWAY_BIND_IP"] = "127.0.0.1"
        updates["TUNNEX_APP_PROXY_GATEWAY_PORT"] = "8444"
        notes.append("the gateway listener is not published today; it stays on loopback (127.0.0.1:8444). "
                     "Set TUNNEX_APP_PROXY_GATEWAY_BIND_IP later to serve remote gateways")
    for key, value in console.items():
        if value or env.get(key):
            updates[key] = value
    if caddy_loses_https:
        updates["TUNNEX_EDGE_HTTPS_PUBLISH"] = args.edge_https_publish
    updates["COMPOSE_PROFILES"] = profiles
    updates["TUNNEX_APP_ACCESS_COMPOSE_SHA256"] = managed_sha
    updates[ADOPTED_FILES] = api["config_files"]
    updates[ADOPTED_HASHES] = ",".join(sha256_file(e) for e in extras)

    print("App Access adopt plan for %s (project %s)" % (directory, project))
    print("  running composition: %s" % api["config_files"])
    print("  restore barrier volume %s, secrets directory %s, proxy image pin: unchanged" % (volume, secrets_dir))
    print("  public listener %s:%s, gateway listener %s" % (public[0], public[1], "%s:%s" % gateway if gateway else "not published"))
    if caddy_loses_https:
        print("  port 443 stays with the proxy, which forwards the console to %s (terminate-and-forward, kept for adopted installs)"
              % console["TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL"])
        print("  Caddy's HTTPS port is published on loopback only: %s" % args.edge_https_publish)
    print("  install the managed overlay as %s (sha256 %s)" % (managed_path, managed_sha))
    print("  .env changes:")
    for key, value in updates.items():
        old = env.get(key)
        if old != value:
            print("    %s: %s -> %s" % (key, "(unset)" if old is None else old or "(empty)", value or "(empty)"))
    print("  record the hand-written overlays (left on disk, no longer used after the upgrade):")
    for extra in extras:
        print("    %s sha256 %s" % (extra, sha256_file(extra)))
    for note in notes:
        print("  note: %s" % note)
    print("  No container is stopped or recreated. The next upgrade recreates the stack from the managed files.")
    if not args.apply:
        print("dry run: nothing was changed; re-run with --apply")
        return 0

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = directory / ("app-access-adopt-" + stamp)
    os.mkdir(str(backup), 0o700)
    shutil.copy2(str(env_file), str(backup / ".env"))
    if managed_path.exists():
        shutil.copy2(str(managed_path), str(backup / "app-access.yml"))
    for extra in extras:
        shutil.copy2(str(extra), str(backup / extra.name))
    restore_overlay = ("  cp %s %s\n" % (backup / "app-access.yml", managed_path)) if (backup / "app-access.yml").exists() \
        else ("  rm %s\n" % managed_path)
    rollback = (
        "Rollback before the upgrade (nothing running was changed by adopt):\n"
        "  cp %s %s\n%s"
        "After the upgrade has run, the hand-written layout cannot be restored; use the upgrade's own rollback\n"
        "(app-access-restore.py with the pre-upgrade backup), see the App Access README.\n"
        % (backup / ".env", env_file, restore_overlay))
    atomic_write(backup / "ROLLBACK.txt", rollback.encode(), 0o600)
    atomic_write(managed_path, managed_overlay, 0o644)
    write_env(env_file, updates)
    print("adopted. Backup and rollback instructions: %s" % backup)
    print(rollback, end="")
    print("Next: %s/upgrade.sh (dry run), then %s/upgrade.sh --apply" % (directory, directory))
    return 0


# --------------------------------------------------------------------------
def _pump(client, server, c_in, c_out, s_in, s_out):
    """Run a TLS handshake between two in-memory endpoints; no network."""
    done = {"client": False, "server": False}
    for _ in range(50):
        for name, obj in (("client", client), ("server", server)):
            if done[name]:
                continue
            try:
                obj.do_handshake()
                done[name] = True
            except ssl.SSLWantReadError:
                pass
        if c_out.pending:
            s_in.write(c_out.read())
        if s_out.pending:
            c_in.write(s_out.read())
        if all(done.values()):
            return
    raise ssl.SSLError("handshake did not complete")


def verify_pair(cert, key, hostnames, cafile=None):
    """Prove chain, hostname coverage, validity window and key match with the
    local TLS library. Returns (not_after, sha256 fingerprint of the leaf)."""
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        server_ctx.load_cert_chain(str(cert), str(key))
    except (ssl.SSLError, OSError):
        raise Refused("the certificate and private key do not match, or cannot be read")
    client_ctx = ssl.create_default_context(cafile=str(cafile) if cafile else None)
    result = None
    for name in hostnames:
        c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
        client = client_ctx.wrap_bio(c_in, c_out, server_hostname=name)
        server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
        try:
            _pump(client, server, c_in, c_out, s_in, s_out)
        except ssl.SSLCertVerificationError as e:
            raise Refused("the certificate does not verify for %s: %s" % (name, e.verify_message))
        except ssl.SSLError as e:
            raise Refused("TLS validation failed for %s: %s" % (name, e.reason or e))
        peer = client.getpeercert()
        result = (datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(peer["notAfter"]), datetime.timezone.utc),
                  hashlib.sha256(client.getpeercert(binary_form=True)).hexdigest())
    return result


def portal_host(env):
    url = env.get("APP_BASE_URL", "")
    rest = url.split("://", 1)[-1]
    host = rest.split("/", 1)[0]
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def proxy_container(project):
    found = participants(project)["app-proxy"]
    if len(found) != 1:
        raise Refused("expected exactly one App Access proxy in project %s, found %d" % (project, len(found)))
    return found[0]["id"]


def restart_and_wait(cid, timeout):
    docker("restart", "--time", "10", cid)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = docker("inspect", "--format", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", cid).split()
        if state[:2] == ["running", "healthy"]:
            return True
        if state and state[0] in ("exited", "dead"):
            return False
        time.sleep(2)
    return False


def renew(args):
    directory = pathlib.Path(args.directory).resolve()
    env = read_env(directory / ".env")
    base = env.get("TUNNEX_APP_ACCESS_BASE_DOMAIN", "").strip(".")
    secrets_dir = pathlib.Path(env.get("TUNNEX_APP_PROXY_SECRETS_DIR", ""))
    if not base or not env.get("TUNNEX_APP_PROXY_SECRETS_DIR"):
        raise Refused("TUNNEX_APP_ACCESS_BASE_DOMAIN and TUNNEX_APP_PROXY_SECRETS_DIR must be set in .env")
    if not secrets_dir.is_absolute() or not secrets_dir.is_dir() or secrets_dir.is_symlink():
        raise Refused("the proxy secrets directory %s is missing or not a plain directory" % secrets_dir)
    cert, key = pathlib.Path(args.cert).resolve(), pathlib.Path(args.key).resolve()
    for path in (cert, key):
        if not path.is_file() or path.stat().st_size > 1 << 20:
            raise Refused("%s is missing or too large" % path)
    # Every application hostname is covered by the wildcard; a random label
    # proves it. With terminate-and-forward the proxy also serves the portal.
    names = ["tnx-%s.%s" % (secrets.token_hex(4), base)]
    if env.get("TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL"):
        portal = portal_host(env)
        if portal and portal not in names:
            names.append(portal)
    not_after, fingerprint = verify_pair(cert, key, names, args.ca_file)
    now = datetime.datetime.now(datetime.timezone.utc)
    if not_after - now < datetime.timedelta(days=args.min_days):
        raise Refused("the certificate expires %s, less than %d days from now" % (not_after.isoformat(), args.min_days))
    current_cert, current_key = secrets_dir / "public-cert.pem", secrets_dir / "public-key.pem"
    current_expiry = None
    if current_cert.is_file() and current_key.is_file():
        try:
            current_expiry, _ = verify_pair(current_cert, current_key, names, args.ca_file)
        except Refused:
            current_expiry = None  # expired or broken: any valid renewal is better
    if current_expiry and not_after <= current_expiry and not args.allow_earlier_expiry:
        raise Refused("the new certificate expires %s, not later than the installed one (%s); "
                      "pass --allow-earlier-expiry to install it anyway" % (not_after.isoformat(), current_expiry.isoformat()))
    print("App Access public certificate renewal for %s" % directory)
    print("  verified for: %s (chain, hostname, validity window, key match)" % ", ".join(names))
    print("  new leaf sha256 %s, expires %s (%d days)" % (fingerprint, not_after.isoformat(), (not_after - now).days))
    print("  installed leaf expires %s" % (current_expiry.isoformat() if current_expiry else "unknown or invalid"))
    print("  install into %s as public-cert.pem/public-key.pem (mode 0400), then restart the proxy (open streams close; clients reconnect)" % secrets_dir)
    if not args.apply:
        print("dry run: nothing was changed; re-run with --apply")
        return 0
    owner = current_cert.stat() if current_cert.exists() else None
    uid, gid = (owner.st_uid, owner.st_gid) if owner else (PROXY_UID, PROXY_UID)
    project = env.get("COMPOSE_PROJECT_NAME") or "tunnex"
    cid = proxy_container(project)
    kept = []
    for name, source in (("public-cert.pem", cert), ("public-key.pem", key)):
        current, previous = secrets_dir / name, secrets_dir / (name + ".previous")
        if previous.exists():
            previous.unlink()
        if current.exists():
            os.link(str(current), str(previous))
            kept.append((current, previous))
        atomic_write(current, source.read_bytes(), 0o400, uid, gid)
    if restart_and_wait(cid, args.restart_timeout):
        print("renewed: the proxy is running and ready with the new certificate. Previous files kept as *.previous")
        return 0
    for current, previous in kept:
        os.replace(str(previous), str(current))
    restored = restart_and_wait(cid, args.restart_timeout)
    raise Refused("the proxy did not become ready with the new certificate; the previous files were restored and the proxy "
                  "was restarted (%s). Inspect: docker logs %s" % ("ready again" if restored else "NOT ready, inspect now", cid), changed=True)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="tunnex-app-access", description=__doc__.split("\n\n")[0])
    # Installed next to upgrade.sh, the command finds its installation by itself.
    default_dir = os.environ.get("TUNNEX_DIR") or (str(HERE) if (HERE / ".env").is_file() else str(pathlib.Path.cwd()))
    parser.add_argument("--directory", default=default_dir,
                        help="installation directory with tunnex.yml and .env (default: this command's directory "
                             "when installed there, else the current directory)")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("adopt", help="convert a hand-written App Access composition into the managed one")
    a.add_argument("--apply", action="store_true")
    a.add_argument("--edge-https-publish", default=DEFAULT_EDGE_HTTPS_PUBLISH,
                   help="loopback publish for Caddy HTTPS when the proxy owns 443 (default %(default)s)")
    a.add_argument("--gateway-host", default=None, help="address following gateways dial; '' for their agent host")
    a.add_argument("--overlay", help=argparse.SUPPRESS)
    a.add_argument("--target-compose", help=argparse.SUPPRESS)
    r = sub.add_parser("renew", help="validate and install a renewed public certificate/key pair")
    r.add_argument("--cert", required=True, help="full chain PEM (for example certbot's fullchain.pem)")
    r.add_argument("--key", required=True, help="private key PEM (for example certbot's privkey.pem)")
    r.add_argument("--ca-file", help="trust bundle for a private CA (default: system trust)")
    r.add_argument("--min-days", type=int, default=7)
    r.add_argument("--allow-earlier-expiry", action="store_true")
    r.add_argument("--restart-timeout", type=int, default=120)
    r.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        return adopt(args) if args.command == "adopt" else renew(args)
    except Refused as e:
        print("error: %s.%s" % (e, "" if e.changed else " Nothing was changed."), file=sys.stderr)
        return 13


if __name__ == "__main__":
    sys.exit(main())
