#!/usr/bin/env python3
"""Bounded SCP proof for an explicitly approved, already running SSH target."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile
import time
from typing import NamedTuple


MAX_PAYLOAD = 1024 * 1024
REMOTE_TEMPLATE = "/tmp/tunnex-scp-roundtrip.XXXXXXXXXXXX"
REMOTE_PATH = re.compile(r"/tmp/tunnex-scp-roundtrip\.[A-Za-z0-9]{12}")
STAGES = ("create_directory", "upload", "remote_hash", "download", "cleanup")


class Config(NamedTuple):
    target: str
    user: str
    known_hosts: str
    identity: str | None = None
    port: int = 22
    payload_bytes: int = 32768
    timeout: int = 15
    pr_number: int | None = None


class Refused(ValueError):
    pass


class CommandFailed(Exception):
    def __init__(self, stage, reason):
        self.stage, self.reason = stage, reason


def reference(value):
    # A path reference only. Never open/stat an identity or known-hosts file.
    if not isinstance(value, str) or not value or len(value) > 2048 or re.search(r'[\x00-\x1f\x7f"\\%$`]', value):
        raise Refused("invalid_openssh_file_reference")
    path = Path(os.path.expanduser(value))
    if not path.is_absolute() or ".." in path.parts:
        raise Refused("absolute_openssh_file_reference_required")
    return str(path)


def validated(cfg):
    if not isinstance(cfg.target, str) or not cfg.target or len(cfg.target) > 253 or "%" in cfg.target:
        raise Refused("invalid_target")
    try:
        ipaddress.ip_address(cfg.target)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", cfg.target):
            raise Refused("invalid_target")
    if not isinstance(cfg.user, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", cfg.user):
        raise Refused("invalid_remote_user")
    for value, low, high in ((cfg.port, 1, 65535), (cfg.payload_bytes, 1024, MAX_PAYLOAD), (cfg.timeout, 1, 30)):
        if type(value) is not int or not low <= value <= high:
            raise Refused("invalid_test_bound")
    if cfg.pr_number is not None and (type(cfg.pr_number) is not int or cfg.pr_number < 1):
        raise Refused("invalid_recorded_pr_number")
    return cfg._replace(known_hosts=reference(cfg.known_hosts),
                        identity=reference(cfg.identity) if cfg.identity is not None else None)


def openssh_options(cfg):
    options = ["-F", "/dev/null"]
    for value in ("BatchMode=yes", "StrictHostKeyChecking=yes",
                  'UserKnownHostsFile="' + cfg.known_hosts + '"', "GlobalKnownHostsFile=/dev/null",
                  "KnownHostsCommand=none", "VerifyHostKeyDNS=no", "UpdateHostKeys=no",
                  "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                  "PreferredAuthentications=publickey", "IdentitiesOnly=yes", "ForwardAgent=no",
                  "ClearAllForwardings=yes", "ProxyCommand=none", "ProxyJump=none",
                  "PermitLocalCommand=no", "ConnectionAttempts=1", "ConnectTimeout=5", "LogLevel=ERROR"):
        options.extend(("-o", value))
    if cfg.identity is not None:
        options.extend(("-i", cfg.identity))
    return options


def ssh(cfg, command):
    return ["ssh", "-n", "-T", *openssh_options(cfg), "-p", str(cfg.port), "--",
            cfg.user + "@" + cfg.target, command]


def scp(cfg, source, destination):
    return ["scp", "-B", "-q", *openssh_options(cfg), "-P", str(cfg.port), "-l", "1024", "--", source, destination]


def payload(size):
    seed = b"TUNNEX_SCP_ROUNDTRIP_V1\n" + bytes(range(256))
    return (seed * ((size + len(seed) - 1) // len(seed)))[:size]


def run_roundtrip(cfg, runner=None):
    cfg = validated(cfg)
    if cfg.pr_number is None:
        raise Refused("recorded_existing_pr_required_before_execution")
    runner = runner or subprocess.run
    summary = {"status": "failed", "pr_number": cfg.pr_number, "payload_bytes": cfg.payload_bytes,
               "operations": {stage: {"result": "not_run", "exit_code": None} for stage in STAGES},
               "private_key_handling": "openssh_reference_only"}
    started = time.monotonic()
    remote = None
    failure = None

    def invoke(stage, args):
        record = summary["operations"][stage]
        try:
            result = runner(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=cfg.timeout, check=False)
        except subprocess.TimeoutExpired:
            record["result"] = "timeout"
            raise CommandFailed(stage, "command_timeout") from None
        except OSError:
            record["result"] = "unavailable"
            raise CommandFailed(stage, "command_unavailable") from None
        record.update(result="passed" if result.returncode == 0 else "failed", exit_code=result.returncode)
        if result.returncode != 0:
            raise CommandFailed(stage, "nonzero_exit")
        if len(result.stdout) > 4096:
            record["result"] = "failed"
            raise CommandFailed(stage, "unexpected_command_output")
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="tunnex-scp-roundtrip-local-") as temporary:
        local = Path(temporary)
        uploaded, downloaded = local / "upload.bin", local / "download.bin"
        raw = payload(cfg.payload_bytes)
        uploaded.write_bytes(raw)
        uploaded.chmod(0o600)
        expected = hashlib.sha256(raw).hexdigest()
        summary["payload_sha256"] = expected
        try:
            output = invoke("create_directory", ssh(cfg, "set -eu\numask 077\nmktemp -d " + REMOTE_TEMPLATE))
            try:
                candidate = output.decode("ascii").removesuffix("\n")
            except UnicodeDecodeError:
                candidate = ""
            if not REMOTE_PATH.fullmatch(candidate):
                summary["operations"]["create_directory"]["result"] = "failed"
                raise CommandFailed("create_directory", "untrusted_remote_path")
            remote = candidate
            remote_file = remote + "/payload.bin"
            host = "[" + cfg.target + "]" if ":" in cfg.target else cfg.target
            endpoint = cfg.user + "@" + host + ":" + remote_file
            invoke("upload", scp(cfg, str(uploaded), endpoint))
            output = invoke("remote_hash", ssh(cfg, "sha256sum < " + shlex.quote(remote_file)))
            match = re.fullmatch(rb"([0-9a-f]{64})[ \t]+-\n?", output)
            if match is None or match[1].decode() != expected:
                summary["operations"]["remote_hash"]["result"] = "failed"
                raise CommandFailed("remote_hash", "uploaded_hash_mismatch")
            summary["uploaded_sha256"] = match[1].decode()
            invoke("download", scp(cfg, endpoint, str(downloaded)))
            info = downloaded.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size != cfg.payload_bytes:
                raise CommandFailed("download", "downloaded_size_mismatch")
            downloaded_raw = downloaded.read_bytes()
            summary["downloaded_sha256"] = hashlib.sha256(downloaded_raw).hexdigest()
            if downloaded_raw != raw:
                raise CommandFailed("download", "downloaded_hash_mismatch")
        except CommandFailed as error:
            failure = error
            record = summary["operations"][error.stage]
            if record["result"] == "passed":
                record["result"] = "failed"
        except OSError:
            failure = CommandFailed("download", "download_unavailable")
            summary["operations"]["download"]["result"] = "failed"
        finally:
            if remote is not None:
                cleanup = "set -eu\nrm -f -- " + shlex.quote(remote + "/payload.bin") + "\nrmdir -- " + shlex.quote(remote)
                try:
                    invoke("cleanup", ssh(cfg, cleanup))
                except CommandFailed as error:
                    failure = failure or error
    summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
    if failure is None:
        summary["status"] = "passed"
    else:
        summary.update(failed_stage=failure.stage, reason=failure.reason)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--identity")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--bytes", type=int, default=32768, dest="payload_bytes")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--pr-number", type=int)
    parser.add_argument("--execute", action="store_true")
    options = vars(parser.parse_args(argv))
    execute = options.pop("execute")
    try:
        cfg = validated(Config(**options))
        if execute:
            summary = run_roundtrip(cfg)
        else:
            summary = {"status": "not_run", "reason": "explicit_execution_required",
                       "pr_number": cfg.pr_number, "payload_bytes": cfg.payload_bytes,
                       "private_key_handling": "openssh_reference_only"}
    except Refused as error:
        parser.error(str(error))
    except OSError:
        summary = {"status": "failed", "reason": "local_fixture_unavailable"}
    print(json.dumps(summary, sort_keys=True))
    return 1 if summary["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
