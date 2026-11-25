#!/usr/bin/env python3
"""tunnex-local-sharing: one-step Local Sharing setup on a Compose host (LS-UX-1 E.2).

  enable   Verify the installed signed release and pin its Local Sharing proxy,
           install the managed overlay, issue the proxy credential (purpose
           local-sharing) and connector certificate, install your wildcard
           certificate, write .env and start the proxy. By default the proxy
           shares this host's public 443 (single-IP edge). Dry run unless
           --apply. Re-running with the same inputs changes nothing.
  disable  Stop and remove the Local Sharing proxy, give public 443 back to its
           previous owner, restore the saved .env values and revoke the proxy
           credential. Settings, policy, history and certificates are kept.
           Dry run unless --apply.
  status   Show what is installed and what is still missing.

Standard library only. Never prints, logs or stores secret material: private
keys and tokens are only copied with private modes, container environment is
never inspected, and only names, paths, fingerprints and dates are shown.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile

PROXY_UID = 10001
HOST_OVERLAY = "/usr/share/tunnex/host/beam/compose.yml"
EDGE_PROXY = "172.31.254.2"
EDGE_CADDY = "172.31.254.3"
CADDY_INTERNAL_PUBLISH = "127.0.0.1:8446"
APP_PROXY_INTERNAL = ("127.0.0.1", "8448")
SAVED = "TUNNEX_LOCAL_SHARING_SAVED_"
MOVED_KEYS = ("TUNNEX_EDGE_HTTPS_PUBLISH", "TUNNEX_APP_PROXY_BIND_IP", "TUNNEX_APP_PROXY_PUBLIC_PORT")
OWNED_KEYS = (
    "TUNNEX_BEAM_BASE_DOMAIN", "TUNNEX_BEAM_PROXY_URL", "TUNNEX_BEAM_PROXY_IMAGE", "TUNNEX_BEAM_PROXY_SECRETS_DIR",
    "TUNNEX_BEAM_PUBLIC_BIND_IP", "TUNNEX_BEAM_CONNECTOR_BIND_IP", "TUNNEX_BEAM_CONNECTOR_PORT",
    "TUNNEX_LOCAL_SHARING_COMPOSE_SHA256", "TUNNEX_BEAM_EDGE_DEFAULT", "TUNNEX_BEAM_EDGE_APP_ACCESS_DOMAIN",
    "TUNNEX_BEAM_EDGE_APP_ACCESS_TARGET", "TUNNEX_EDGE_PROXY_PROTOCOL_FROM", "TUNNEX_APP_PROXY_EDGE_TOKEN_FILE",
    "TUNNEX_LOCAL_SHARING_CREDENTIAL_ID", "TUNNEX_LOCAL_SHARING_CREDENTIAL_VERSION", "TUNNEX_BEAM_EDGE_DEFAULT_TOKEN",
)
BEAM_SERVICES = ("beam-proxy", "beam-restore-init")
HOST_RE = re.compile(r"^(?=.{4,218}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class Refused(Exception):
    pass


def say(line=""):
    print(line, flush=True)


def sha256_file(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


# .env is data, never shell.
def read_env(path):
    values = {}
    for line in pathlib.Path(path).read_text().splitlines():
        if line and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values.setdefault(key, value)
    return values


def write_env(path, updates, removals=()):
    path = pathlib.Path(path)
    for key, value in updates.items():
        if "\n" in value or "\r" in value:
            raise Refused("refusing a multi-line .env value for %s" % key)
    lines, seen = [], set()
    for line in path.read_text().splitlines():
        key = line.split("=", 1)[0] if "=" in line and not line.lstrip().startswith("#") else None
        if key in removals:
            continue
        if key in updates:
            if key not in seen:
                lines.append("%s=%s" % (key, updates[key]))
                seen.add(key)
            continue
        lines.append(line)
    lines += ["%s=%s" % (k, v) for k, v in updates.items() if k not in seen]
    atomic_write(path, ("\n".join(lines) + "\n").encode(), os.stat(path).st_mode & 0o777)


def atomic_write(path, data, mode, owner=False):
    path = pathlib.Path(path)
    tmp = path.with_name(path.name + ".next")
    if tmp.exists():
        tmp.unlink()
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if owner and os.geteuid() == 0:
            os.fchown(fd, PROXY_UID, PROXY_UID)
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))


def private_dir(path):
    path = pathlib.Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    if os.geteuid() == 0:
        os.chown(path, PROXY_UID, PROXY_UID)
    return path


class Host:
    """The installation: directory, .env and its current Compose files."""

    def __init__(self, directory):
        self.dir = pathlib.Path(directory).resolve()
        self.env_file = self.dir / ".env"
        if not self.env_file.is_file() or not (self.dir / "tunnex.yml").is_file():
            raise Refused("%s is not a Tunnex installation directory (no .env or tunnex.yml)" % self.dir)
        self.env = read_env(self.env_file)
        self.overlay = self.dir / "local-sharing.yml"
        self.app_access = (self.dir / "app-access.yml").is_file() and bool(self.env.get("TUNNEX_APP_ACCESS_COMPOSE_SHA256"))
        self.project = self.env.get("COMPOSE_PROJECT_NAME") or "tunnex"

    def files(self, local_sharing):
        files = [self.dir / "tunnex.yml"] + ([self.dir / "app-access.yml"] if self.app_access else [])
        return files + ([self.overlay] if local_sharing else [])

    def compose(self, *args, local_sharing=True, extra=(), profiles=None, capture=True, env_file=None):
        # env_file: a complete staged copy of .env (LS-FIX-1). Compose reads only
        # this file for interpolation, so it must hold every setting.
        env_file = env_file or self.env_file
        env = dict(os.environ)
        env["COMPOSE_PROFILES"] = profiles if profiles is not None else read_env(env_file).get("COMPOSE_PROFILES", "bundled-db")
        cmd = ["docker", "compose", "--project-name", self.project, "--env-file", str(env_file)]
        for f in list(self.files(local_sharing)) + list(extra):
            cmd += ["-f", str(f)]
        result = subprocess.run(cmd + list(args), capture_output=capture, env=env)
        if result.returncode != 0:
            detail = (result.stderr or b"").decode(errors="replace").strip()[-300:]
            raise Refused("docker compose %s failed%s" % (args[0], (": " + detail) if detail else ""))
        return (result.stdout or b"").decode()

    def up(self, services, **kw):
        """Start exactly these services (and what they depend on). Never an
        unnamed `up`: that would also start every service no profile hides,
        such as a stopped node-agent (LS-FIX-1)."""
        if services:
            self.compose("up", "-d", "--wait", "--wait-timeout", "300", *sorted(services), capture=False, **kw)

    def running(self):
        """Compose participants of this project: {service: (config_files, running)}.
        Labels and container state only."""
        out = subprocess.run(["docker", "ps", "-a", "--filter", "label=com.docker.compose.project=" + self.project, "--format", "{{.ID}}"],
                             capture_output=True, text=True)
        if out.returncode != 0:
            raise Refused("could not inspect the running installation")
        found = {}
        for cid in out.stdout.split():
            info = subprocess.run(["docker", "inspect", "--format",
                                   '{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}|{{index .Config.Labels "com.docker.compose.oneoff"}}|{{.State.Running}}', cid],
                                  capture_output=True, text=True)
            if info.returncode != 0 or info.stdout.count("|") != 3:
                raise Refused("could not inspect the running installation")
            service, files, oneoff, running = info.stdout.strip().split("|")
            if oneoff != "True":
                files_seen, was_running = found.get(service, (files, False))
                found[service] = (files_seen, was_running or running == "true")
        return found

    def running_services(self):
        """The services running now: the only ones enable, disable and a
        rollback may (re)start, besides Local Sharing's own."""
        return {service for service, (_, running) in self.running().items() if running}

    def check_layout(self):
        """Refuse unless the running stack is exactly what this command composes."""
        running = {service: files for service, (files, _) in self.running().items()}
        if "app-proxy" in running and not self.app_access:
            raise Refused("App Access is installed but not in the managed layout (tunnex.yml + app-access.yml); "
                          "adopt or upgrade App Access first, then run this again")
        expected = {",".join(str(f) for f in self.files(False)), ",".join(str(f) for f in self.files(True))}
        if "api" not in running:
            raise Refused("the Tunnex API is not running in project %s; start Tunnex first" % self.project)
        if running["api"] not in expected:
            raise Refused("the running stack uses %s, not the managed files this command uses (%s); "
                          "converge it with upgrade.sh first" % (running["api"], " or ".join(sorted(expected))))

    def base_profile(self):
        return "external-db" if self.env.get("TUNNEX_DATABASE_MODE") == "external" else "bundled-db"


def console_host(env):
    url = env.get("APP_BASE_URL", "")
    m = re.match(r"^https://([A-Za-z0-9.-]+)(:\d+)?/?$", url)
    if not m:
        raise Refused("APP_BASE_URL in .env must be the console's https:// address")
    return m.group(1).lower()


def check_domain(domain, env):
    """Obvious mistakes only; the console enforces the public-suffix rule when
    the domain is saved (a sibling of the console would share its cookies)."""
    if not HOST_RE.match(domain):
        raise Refused("--domain must be a DNS name such as share-example.dev (no scheme, wildcard or port)")
    console = console_host(env)
    def overlaps(a, b):
        return bool(a and b) and (a == b or a.endswith("." + b) or b.endswith("." + a))
    if overlaps(domain, env.get("TUNNEX_APP_ACCESS_BASE_DOMAIN", "").lower()):
        raise Refused("the sharing domain overlaps the App Access domain; use a separate domain")
    if domain.endswith("." + console) or console.endswith("." + domain):
        raise Refused("the sharing domain must be a registrable domain of its own, not under or above the console (%s)" % console)


def _pump(client, server, c_in, c_out, s_in, s_out):
    for _ in range(64):
        done = True
        for side in (client, server):
            try:
                side.do_handshake()
            except ssl.SSLWantReadError:
                done = False
        data = c_out.read()
        if data:
            s_in.write(data)
        data = s_out.read()
        if data:
            c_in.write(data)
        if done:
            return
    raise ssl.SSLError("handshake did not complete")


def verify_pair(cert, key, name, cafile=None):
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        server_ctx.load_cert_chain(str(cert), str(key))
    except (ssl.SSLError, OSError):
        raise Refused("the certificate and private key do not match, or cannot be read")
    client_ctx = ssl.create_default_context(cafile=str(cafile) if cafile else None)
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname=name)
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    try:
        _pump(client, server, c_in, c_out, s_in, s_out)
    except ssl.SSLCertVerificationError as e:
        raise Refused("the certificate is not trusted for %s: %s" % (name, e.verify_message))
    except ssl.SSLError as e:
        raise Refused("TLS validation failed for %s: %s" % (name, e.reason or e))
    peer = client.getpeercert()
    not_after = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(peer["notAfter"]), datetime.timezone.utc)
    return not_after, hashlib.sha256(client.getpeercert(binary_form=True)).hexdigest()


def helper_overlay(tmp, out):
    path = pathlib.Path(tmp) / "local-sharing-issue.yml"
    path.write_text("services:\n  api:\n    volumes:\n"
                    "      - {type: volume, source: app_restore, target: /var/lib/tunnex/app-restore, read_only: false}\n"
                    "      - {type: bind, source: '%s', target: /out}\n" % out)
    return path


def backupctl(host, out, *args, env_file=None, local_sharing=True):
    with tempfile.TemporaryDirectory() as tmp:
        return host.compose("run", "--rm", "--no-deps", "-T", "--pull", "never", "--entrypoint", "backupctl", "api", *args,
                            extra=[helper_overlay(tmp, out)], profiles=host.base_profile(), env_file=env_file,
                            local_sharing=local_sharing)


def stage_env(host, directory, updates):
    """A complete private copy of .env with the planned settings (LS-FIX-1).
    Every compose call that includes the overlay before .env is written uses
    it, so interpolation never meets a missing TUNNEX_BEAM_* value."""
    staged = pathlib.Path(directory) / "env"
    fd = os.open(str(staged), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, host.env_file.read_bytes())
    finally:
        os.close(fd)
    write_env(staged, updates)
    return staged


def edge_plan(host, env):
    """443 ownership changes for the single-IP edge. Returns (updates, saved, notes)."""
    if env.get("TUNNEX_TLS_MODE", "") not in ("", "direct"):
        raise Refused("the single-IP edge needs this host to serve the console over HTTPS directly; "
                      "use --layout dedicated --public-ip ADDRESS instead")
    updates, notes = {"TUNNEX_EDGE_PROXY_PROTOCOL_FROM": EDGE_PROXY + "/32"}, []
    caddy = env.get("TUNNEX_EDGE_HTTPS_PUBLISH", "")
    if caddy in ("", "443", "0.0.0.0:443", ":443"):
        updates["TUNNEX_EDGE_HTTPS_PUBLISH"] = CADDY_INTERNAL_PUBLISH
    default = EDGE_CADDY + ":443"
    if host.app_access:
        if env.get("TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL"):
            default = "app-proxy:8443"  # app-proxy already forwards the console
            updates["TUNNEX_BEAM_EDGE_DEFAULT_TOKEN"] = "true"
        else:
            updates["TUNNEX_BEAM_EDGE_APP_ACCESS_DOMAIN"] = env.get("TUNNEX_APP_ACCESS_BASE_DOMAIN", "")
            updates["TUNNEX_BEAM_EDGE_APP_ACCESS_TARGET"] = "app-proxy:8443"
        if env.get("TUNNEX_APP_PROXY_PUBLIC_PORT", "443") in ("", "443"):
            updates["TUNNEX_APP_PROXY_BIND_IP"], updates["TUNNEX_APP_PROXY_PUBLIC_PORT"] = APP_PROXY_INTERNAL
        updates["TUNNEX_APP_PROXY_EDGE_TOKEN_FILE"] = "/etc/tunnex/app-proxy/edge.token"
        notes.append("App Access keeps working: its traffic reaches app-proxy through the edge, undecrypted")
    updates["TUNNEX_BEAM_EDGE_DEFAULT"] = default
    updates["TUNNEX_BEAM_PUBLIC_BIND_IP"] = "0.0.0.0"
    saved = {SAVED + k: env.get(k, "") for k in MOVED_KEYS if k in updates and SAVED + k not in env}
    return updates, saved, notes


def enable(args):
    host = Host(args.directory)
    env = host.env
    domain = args.domain.strip().lower().rstrip(".")
    check_domain(domain, env)
    console = console_host(env)
    port = str(args.connector_port)
    if not port.isdigit() or not 1 <= int(port) <= 65535 or port in ("443", "8443", "8444", "8445", "9093"):
        raise Refused("--connector-port must be a free TCP port such as 8447 (not 443, 8443-8445 or 9093)")
    cert, key = pathlib.Path(args.cert), pathlib.Path(args.key)
    not_after, fingerprint = verify_pair(cert, key, "tunnex-check." + domain, args.ca_file)
    if not_after - datetime.datetime.now(datetime.timezone.utc) < datetime.timedelta(days=7):
        raise Refused("the wildcard certificate expires in less than 7 days (%s)" % not_after.date())

    say("Local Sharing enable plan for %s (project %s)" % (host.dir, host.project))
    say("  sharing domain %s, console %s, connector https://%s:%s" % (domain, console, console, port))
    say("  certificate *.%s valid until %s (sha256 %s…)" % (domain, not_after.date(), fingerprint[:16]))
    pin = host.compose("exec", "-T", "api", "sh", "-c",
                       'releaseverify -manifest /var/lib/tunnex/release.json -public-key "$TUNNEX_RELEASE_PUBLIC_KEY" -require-beam-proxy -print-env',
                       local_sharing=False)
    image = next((l.split("=", 1)[1] for l in pin.splitlines() if l.startswith("TUNNEX_BEAM_PROXY_IMAGE=")), "")
    if not re.fullmatch(r"ghcr\.io/tunnexio/tunnex-beam-proxy@sha256:[0-9a-f]{64}", image):
        raise Refused("the installed release has no signed Local Sharing proxy; upgrade to a release that includes it")
    say("  signed proxy %s" % image)

    secrets_dir = host.dir / "local-sharing" / "secrets"
    updates = {
        "TUNNEX_BEAM_BASE_DOMAIN": domain,
        "TUNNEX_BEAM_PROXY_URL": "https://%s:%s" % (console, port),
        "TUNNEX_BEAM_PROXY_IMAGE": image,
        "TUNNEX_BEAM_PROXY_SECRETS_DIR": str(secrets_dir),
        "TUNNEX_BEAM_CONNECTOR_BIND_IP": "0.0.0.0",
        "TUNNEX_BEAM_CONNECTOR_PORT": port,
    }
    saved, notes = {}, []
    if args.layout == "edge":
        edge, saved, notes = edge_plan(host, env)
        updates.update(edge)
        say("  layout: single-IP edge; the proxy takes public 443 and passes the console%s through undecrypted"
            % (" and App Access" if host.app_access else ""))
    else:
        if not args.public_ip:
            raise Refused("--layout dedicated needs --public-ip (the address for *.%s on port 443)" % domain)
        updates["TUNNEX_BEAM_PUBLIC_BIND_IP"] = args.public_ip
        say("  layout: dedicated address %s:443 for shares" % args.public_ip)
    profiles = [p for p in env.get("COMPOSE_PROFILES", host.base_profile()).split(",") if p]
    if "beam" not in profiles:
        updates["COMPOSE_PROFILES"] = ",".join(profiles + ["beam"])
        saved.setdefault(SAVED + "COMPOSE_PROFILES", env.get("COMPOSE_PROFILES", ""))
    changes = {k: v for k, v in {**updates, **saved}.items() if env.get(k) != v}
    say("  .env changes:" if changes else "  .env: unchanged")
    for k, v in changes.items():
        say("    %s=%s" % (k, v))
    for note in notes:
        say("  note: " + note)
    if not args.apply:
        say("dry run: nothing was changed. Re-run with --apply.")
        return 0
    if os.geteuid() != 0 and not args.skip_owner_check:
        raise Refused("run with sudo: the proxy runs as uid %d and must own its private files" % PROXY_UID)
    host.check_layout()
    # Recorded before any change: the only services this run may (re)start.
    before = host.running_services()
    env_before = host.env_file.read_bytes()
    overlay_before = host.overlay.read_bytes() if host.overlay.is_file() else None
    # started: the final `up` ran. issued: (id, version) of a credential this
    # run issued. created: secret files this run created (removed on rollback).
    state = {"started": False, "issued": None, "created": []}
    with tempfile.TemporaryDirectory(prefix="tunnex-local-sharing-") as stage_dir:
        staged = stage_env(host, stage_dir, {**updates, **saved})
        try:
            return apply_enable(args, host, env, domain, console, port, updates, saved, secrets_dir, cert, key,
                                staged, before, state)
        except Exception as e:
            raise Refused("enable failed (%s); %s" % (e, rollback_enable(host, before, state, staged, env_before, overlay_before)))


def rollback_enable(host, before, state, staged, env_before, overlay_before):
    """Put the previous setup back without starting anything that was not running.
    Never leaves public 443 held by a proxy the restored setup does not know."""
    removal_failed, unrevoked = False, ""
    if state["started"] and "beam-proxy" not in before:
        # While the overlay and staged settings still describe it.
        try:
            host.compose("rm", "-s", "-f", *BEAM_SERVICES, env_file=staged)
        except Refused:
            removal_failed = True
    if state["issued"]:
        # The restored .env does not know this credential, so disable could never
        # revoke it: revoke it now and let the next enable issue a fresh one.
        credential_id, version = state["issued"]
        out = private_dir(host.dir / "local-sharing" / ("revoke-" + secrets.token_hex(4)))
        try:
            backupctl(host, out, "app-proxy-revoke", "--id", credential_id, "--expected-version", version, env_file=staged)
        except Refused:
            unrevoked = ("; the proxy credential %s issued by this run could not be revoked: "
                         "revoke it with backupctl app-proxy-revoke" % credential_id)
        finally:
            shutil.rmtree(out, ignore_errors=True)
    for path in state["created"]:
        if path.exists():
            path.unlink()
    atomic_write(host.env_file, env_before, os.stat(host.env_file).st_mode & 0o777)
    if overlay_before is None:
        if host.overlay.exists():
            host.overlay.unlink()
    else:
        atomic_write(host.overlay, overlay_before, 0o644)
    if not state["started"]:
        return "the previous setup was restored; no running service was changed" + unrevoked
    try:
        if removal_failed:
            raise Refused("beam-proxy could not be removed")
        host.up(before, local_sharing=overlay_before is not None)
        return "the previous setup was restored and is running" + unrevoked
    except Refused:
        return "restoring the previous setup also failed; run: %s disable --apply%s" % (sys.argv[0], unrevoked)


def apply_enable(args, host, env, domain, console, port, updates, saved, secrets_dir, cert, key, staged, before, state):
    # 1. Managed overlay from the running signed API image.
    with tempfile.TemporaryDirectory() as tmp:
        signed = pathlib.Path(tmp) / "compose.yml"
        host.compose("cp", "api:" + HOST_OVERLAY, str(signed), local_sharing=False)
        if not host.overlay.is_file() or host.overlay.read_bytes() != signed.read_bytes():
            atomic_write(host.overlay, signed.read_bytes(), 0o644)
            say("installed the managed overlay %s" % host.overlay)
    updates["TUNNEX_LOCAL_SHARING_COMPOSE_SHA256"] = sha256_file(host.overlay)
    # 2. Credential and connector certificate (only when missing).
    private_dir(secrets_dir)
    if not (secrets_dir / "authority.token").is_file() or not (secrets_dir / "gateway-cert.pem").is_file():
        out = private_dir(host.dir / "local-sharing" / ("issue-" + secrets.token_hex(4)))
        try:
            if not (secrets_dir / "authority.token").is_file():
                issued = json.loads(backupctl(host, out, "app-proxy-issue", "--purpose", "local-sharing",
                                              "--name", "local-sharing-" + console, "--output", "/out/authority.token",
                                              env_file=staged))
                state["issued"] = (issued["id"], str(issued["version"]))
                state["created"].append(secrets_dir / "authority.token")
                updates["TUNNEX_LOCAL_SHARING_CREDENTIAL_ID"] = issued["id"]
                updates["TUNNEX_LOCAL_SHARING_CREDENTIAL_VERSION"] = str(issued["version"])
                shutil.move(str(out / "authority.token"), str(secrets_dir / "authority.token"))
                say("issued the Local Sharing proxy credential %s" % issued["id"])
            if not (secrets_dir / "gateway-cert.pem").is_file():
                state["created"] += [secrets_dir / n for n in ("gateway-cert.pem", "gateway-key.pem", "agent-ca.pem")]
                backupctl(host, out, "beam-proxy-certificate", "--output-dir", "/out/connector", env_file=staged)
                for name in ("gateway-cert.pem", "gateway-key.pem", "agent-ca.pem"):
                    shutil.move(str(out / "connector" / name), str(secrets_dir / name))
                say("issued the connector certificate (TLS name tunnex-beam-proxy)")
        finally:
            shutil.rmtree(out, ignore_errors=True)
    # 3. Wildcard certificate and edge token.
    for source, target in ((cert, "public-cert.pem"), (key, "public-key.pem")):
        data = source.read_bytes()
        if not (secrets_dir / target).is_file() or (secrets_dir / target).read_bytes() != data:
            atomic_write(secrets_dir / target, data, 0o400, owner=True)
    for name in ("authority.token", "gateway-key.pem", "gateway-cert.pem", "agent-ca.pem"):
        if (secrets_dir / name).is_file():
            os.chmod(secrets_dir / name, 0o400)
            if os.geteuid() == 0:
                os.chown(secrets_dir / name, PROXY_UID, PROXY_UID)
    if args.layout == "edge":
        if not (secrets_dir / "edge.token").is_file():
            atomic_write(secrets_dir / "edge.token", (secrets.token_hex(32) + "\n").encode(), 0o400, owner=True)
        if host.app_access:
            aa_secrets = pathlib.Path(env.get("TUNNEX_APP_PROXY_SECRETS_DIR", ""))
            if not aa_secrets.is_absolute() or not aa_secrets.is_dir():
                raise Refused("TUNNEX_APP_PROXY_SECRETS_DIR in .env must name the App Access secrets directory")
            token = (secrets_dir / "edge.token").read_bytes()
            if not (aa_secrets / "edge.token").is_file() or (aa_secrets / "edge.token").read_bytes() != token:
                atomic_write(aa_secrets / "edge.token", token, 0o400, owner=True)
    # 4. Settings, then start.
    final = {k: v for k, v in {**updates, **saved}.items() if read_env(host.env_file).get(k) != v}
    if final:
        write_env(host.env_file, final)
    # Only what ran before, plus the proxy (beam-restore-init is its dependency).
    state["started"] = True
    host.up(before | {"beam-proxy"})
    say("")
    say("Local Sharing is running. What is left:")
    say("  1. DNS: create *.%s pointing to this server's public address%s." % (
        domain, "" if args.layout == "edge" else " " + args.public_ip))
    say("  2. Firewall: allow TCP 443 from everyone and TCP %s from the people who publish." % port)
    say("  3. Console (server administrator): Settings → Local Sharing domain → enter %s and https://%s:%s,"
        % (domain, console, port))
    say("     allow Local Sharing, save, then select Check DNS and TLS.")
    say("  4. Console (organization admin): set the sharing policy, then Settings → Features → Local Sharing.")
    return 0


def disable(args):
    host = Host(args.directory)
    env = host.env
    saved = {k[len(SAVED):]: v for k, v in env.items() if k.startswith(SAVED)}
    restore = {k: v for k, v in saved.items() if v and k != "COMPOSE_PROFILES"}
    profiles = [p for p in env.get("COMPOSE_PROFILES", "").split(",") if p and p != "beam"]
    restore["COMPOSE_PROFILES"] = ",".join(profiles) or host.base_profile()
    # Keys that were unset before enable are removed again.
    removals = {k for k in env if k.startswith(SAVED) or k in OWNED_KEYS}
    removals |= {k for k, v in saved.items() if not v and k != "COMPOSE_PROFILES"}
    say("Local Sharing disable plan for %s" % host.dir)
    say("  stop and remove beam-proxy; public 443 returns to %s" % ("App Access" if "TUNNEX_APP_PROXY_PUBLIC_PORT" in saved else "the console edge"))
    for k, v in restore.items():
        say("  restore %s=%s" % (k, v))
    if env.get("TUNNEX_LOCAL_SHARING_CREDENTIAL_ID"):
        say("  revoke proxy credential %s" % env["TUNNEX_LOCAL_SHARING_CREDENTIAL_ID"])
    say("  kept: sharing settings and policy, history, certificates in %s" % (host.dir / "local-sharing"))
    if not args.apply:
        say("dry run: nothing was changed. Re-run with --apply.")
        return 0
    # Recorded before any change: the only services restarted afterwards.
    before = host.running_services() - set(BEAM_SERVICES)
    if host.overlay.is_file():
        host.compose("rm", "-s", "-f", *BEAM_SERVICES, profiles=read_env(host.env_file).get("COMPOSE_PROFILES", ""))
    if env.get("TUNNEX_LOCAL_SHARING_CREDENTIAL_ID") and env.get("TUNNEX_LOCAL_SHARING_CREDENTIAL_VERSION"):
        out = private_dir(host.dir / "local-sharing" / ("revoke-" + secrets.token_hex(4)))
        try:
            backupctl(host, out, "app-proxy-revoke", "--id", env["TUNNEX_LOCAL_SHARING_CREDENTIAL_ID"],
                      "--expected-version", env["TUNNEX_LOCAL_SHARING_CREDENTIAL_VERSION"], local_sharing=host.overlay.is_file())
        finally:
            shutil.rmtree(out, ignore_errors=True)
        token = host.dir / "local-sharing" / "secrets" / "authority.token"
        if token.exists():
            token.unlink()
    write_env(host.env_file, restore, removals=removals - set(restore))
    if host.overlay.is_file():
        os.replace(str(host.overlay), str(host.overlay) + ".disabled")
    host.up(before, local_sharing=False)
    say("Local Sharing is off. Shares stopped; settings and policy are kept. Run enable again to turn it back on.")
    return 0


def status(args):
    host = Host(args.directory)
    env = host.env
    checks = [
        ("managed overlay", host.overlay.is_file() and sha256_file(host.overlay) == env.get("TUNNEX_LOCAL_SHARING_COMPOSE_SHA256")),
        ("signed proxy pinned", bool(re.fullmatch(r"ghcr\.io/tunnexio/tunnex-beam-proxy@sha256:[0-9a-f]{64}", env.get("TUNNEX_BEAM_PROXY_IMAGE", "")))),
        ("beam profile", "beam" in env.get("COMPOSE_PROFILES", "").split(",")),
        ("proxy credential", (host.dir / "local-sharing/secrets/authority.token").is_file()),
        ("connector certificate", (host.dir / "local-sharing/secrets/gateway-cert.pem").is_file()),
        ("wildcard certificate", (host.dir / "local-sharing/secrets/public-cert.pem").is_file()),
    ]
    say("Local Sharing on %s: %s layout" % (host.dir, "single-IP edge" if env.get("TUNNEX_BEAM_EDGE_DEFAULT") else "dedicated-address" if env.get("TUNNEX_BEAM_PUBLIC_BIND_IP") else "not enabled"))
    for name, ok in checks:
        say("  %-22s %s" % (name, "ok" if ok else "missing — run: tunnex-local-sharing enable ..."))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="tunnex-local-sharing", description=__doc__.split("\n\n")[0])
    parser.add_argument("--directory", default=str(pathlib.Path(__file__).resolve().parent), help="installation directory (default: this command's directory)")
    sub = parser.add_subparsers(dest="command", required=True)
    e = sub.add_parser("enable", help="set up and start Local Sharing (dry run unless --apply)")
    e.add_argument("--domain", required=True, help="sharing domain, e.g. share-example.dev")
    e.add_argument("--cert", required=True, help="wildcard full-chain PEM for *.DOMAIN")
    e.add_argument("--key", required=True, help="its private key PEM")
    e.add_argument("--connector-port", default="8447", help="TCP port publishers connect to (default 8447)")
    e.add_argument("--ca-file", help="trust bundle for a private CA (default: system trust)")
    e.add_argument("--layout", choices=("edge", "dedicated"), default="edge", help="edge: share this host's 443 (default); dedicated: own address")
    e.add_argument("--public-ip", help="with --layout dedicated: the address for *.DOMAIN on 443")
    e.add_argument("--apply", action="store_true")
    e.add_argument("--skip-owner-check", action="store_true", help=argparse.SUPPRESS)  # tests only: no root
    d = sub.add_parser("disable", help="stop Local Sharing and give 443 back (dry run unless --apply)")
    d.add_argument("--apply", action="store_true")
    sub.add_parser("status", help="show what is installed and missing")
    args = parser.parse_args(argv)
    try:
        return {"enable": enable, "disable": disable, "status": status}[args.command](args)
    except Refused as e:
        print("error: %s. Nothing else was changed." % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
