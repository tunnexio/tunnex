#!/usr/bin/env python3
"""Assemble public enrollment configuration offline; never activate a runner."""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import sys
import uuid
from urllib.parse import urlsplit, urlunsplit


MAX_PUBLIC = 32768
MAX_CONFIG = 16384
ARCHIVE = "tunnex-sandbox-ubuntu26-linux-amd64.docker.tar"


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def text(value, maximum=2048):
    need(isinstance(value, str) and 0 < len(value) <= maximum
         and not any(ord(c) < 32 or ord(c) == 127 for c in value), "invalid_public_value")
    return value


def pin(value, size=64):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % size, value), "invalid_immutable_pin")
    return value


def digest(value):
    need(isinstance(value, str) and value.startswith("sha256:"), "invalid_config_digest")
    return "sha256:" + pin(value[7:])


def identity(value):
    need(isinstance(value, str), "invalid_identity")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise Refused("invalid_identity") from None
    need(str(parsed) == value and parsed.int != 0, "invalid_identity")
    return value


def reference(value):
    text(value, 4096)
    need(value.startswith("/") and posixpath.normpath(value) == value and "//" not in value,
         "absolute_clean_file_reference_required")
    return value


def https(value, origin=False):
    text(value)
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise Refused("invalid_https_url") from None
    need(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
         and not parsed.query and not parsed.fragment and (port is None or 1 <= port <= 65535)
         and (not origin or parsed.path in ("", "/")), "public_https_url_required")
    return value


def spiffe(value):
    text(value)
    parsed = urlsplit(value)
    need(parsed.scheme == "spiffe" and parsed.hostname and not parsed.username and not parsed.password
         and not parsed.query and not parsed.fragment and parsed.path.startswith("/")
         and parsed.path != "/" and not parsed.port, "scoped_spiffe_identity_required")
    return value


def endpoint(value, ipv4=False):
    text(value, 128)
    try:
        parsed = urlsplit("https://" + value)
        address = ipaddress.ip_address(parsed.hostname or "")
        # Match Go net.IP.IsPrivate rather than Python's larger non-global set.
        networks = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("fc00::/7"))
        valid = any(address in network for network in networks) and (not ipv4 or address.version == 4)
        need(valid and parsed.port and 1 <= parsed.port <= 65535 and parsed.netloc == value
             and not parsed.username and not parsed.password and not parsed.path
             and not parsed.query and not parsed.fragment, "private_ip_endpoint_required")
    except ValueError:
        raise Refused("private_ip_endpoint_required") from None
    return value


def keys(value, expected):
    need(isinstance(value, dict) and set(value) == set(expected), "unsupported_public_schema")


def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "duplicate_public_field")
        out[key] = value
    return out


def public_bytes(path, maximum=MAX_PUBLIC):
    """Read only an explicitly supplied public artifact, never a key reference."""
    path = Path(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022 and 0 < info.st_size <= maximum,
         "unsafe_public_input")
    with path.open("rb") as stream:
        current = os.fstat(stream.fileno())
        need((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), "changed_public_input")
        raw = stream.read(maximum + 1)
    need(0 < len(raw) <= maximum, "oversized_public_input")
    return raw


def public_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refused("invalid_public_json")))
    except (UnicodeError, json.JSONDecodeError):
        raise Refused("invalid_public_json") from None


def artifact(value):
    keys(value, ("url", "sha256"))
    https(value["url"])
    pin(value["sha256"])
    return dict(value)


def public_ca(path):
    raw = public_bytes(path, 16384)
    try:
        pem = raw.decode("ascii").strip()
        match = re.fullmatch(r"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)\s+-----END CERTIFICATE-----", pem)
        need(match and len(base64.b64decode("".join(match[1].split()), validate=True)) > 0,
             "public_certificate_pem_required")
    except (UnicodeError, ValueError):
        raise Refused("public_certificate_pem_required") from None
    # The API additionally validates X.509 CA/signing compatibility on startup.
    return pem + "\n"


def verified_inputs(options):
    source = pin(options.source_sha, 40)
    raw = public_bytes(options.distribution)
    need(hashlib.sha256(raw).hexdigest() == pin(options.distribution_sha256), "distribution_checksum_mismatch")
    distribution = public_json(raw)
    keys(distribution, ("schema_version", "source_sha", "repository", "release_tag", "os", "api_editions",
                        "bootstrap_script", "bundles", "installer_architectures", "native_runtime_qualification",
                        "workload_images_built", "workload_image_delivery"))
    need(type(distribution["schema_version"]) is int and distribution["schema_version"] == 1
         and distribution["source_sha"] == source and distribution["os"] == "linux"
         and distribution["installer_architectures"] == ["amd64"]
         and distribution["native_runtime_qualification"] is False
         and distribution["workload_images_built"] is True, "unsupported_distribution")
    text(distribution["repository"], 256)
    text(distribution["release_tag"], 128)
    need(isinstance(distribution["api_editions"], list) and options.edition in distribution["api_editions"]
         and len(set(distribution["api_editions"])) == len(distribution["api_editions"])
         and set(distribution["api_editions"]) <= {"open", "enterprise"}, "unsupported_api_edition")
    keys(distribution["bundles"], ("amd64", "arm64"))
    for bundle in distribution["bundles"].values():
        artifact(bundle)
    artifact(distribution["bootstrap_script"])
    descriptor_pin = artifact(distribution["workload_image_delivery"])
    raw_descriptor = public_bytes(options.workload_descriptor)
    need(hashlib.sha256(raw_descriptor).hexdigest() == descriptor_pin["sha256"], "descriptor_checksum_mismatch")
    descriptor = public_json(raw_descriptor)
    keys(descriptor, ("schema_version", "source_sha", "os", "architecture", "dependency_lock_sha256",
                      "base_manifest_digest", "archive", "config_digest", "unpacked_image_bytes",
                      "native_qualification", "services_started", "packages_installed_at_launch"))
    need(type(descriptor["schema_version"]) is int and descriptor["schema_version"] == 1
         and descriptor["source_sha"] == source and descriptor["os"] == "linux"
         and descriptor["architecture"] == "amd64" and descriptor["native_qualification"] is False
         and descriptor["services_started"] is False and descriptor["packages_installed_at_launch"] is False,
         "unsupported_workload_descriptor")
    pin(descriptor["dependency_lock_sha256"])
    digest(descriptor["base_manifest_digest"])
    digest(descriptor["config_digest"])
    keys(descriptor["archive"], ("filename", "sha256", "bytes"))
    need(descriptor["archive"]["filename"] == ARCHIVE
         and type(descriptor["archive"]["bytes"]) is int and 0 < descriptor["archive"]["bytes"] <= 512 << 20
         and type(descriptor["unpacked_image_bytes"]) is int and 0 < descriptor["unpacked_image_bytes"] <= 1 << 30,
         "unsupported_workload_size")
    pin(descriptor["archive"]["sha256"])
    return distribution, descriptor


def assemble(options):
    distribution, descriptor = verified_inputs(options)
    org = identity(options.org_id)
    gateway_id = identity(options.gateway_node_id)
    pin(options.gateway_container_id)
    digest(options.gateway_image_digest)
    need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", options.gateway_interface), "invalid_gateway_interface")
    listen = endpoint(options.controller_listen)
    controller_url = https(options.controller_url, True)
    controller = urlsplit(controller_url)
    need(endpoint(controller.netloc) == listen, "controller_listener_url_mismatch")
    server_name = text(options.controller_server_name, 253)
    need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", server_name), "tls_server_name_required")
    controller_uri, runner_uri = spiffe(options.controller_uri), spiffe(options.runner_uri)
    need(controller_uri != runner_uri, "distinct_machine_controller_identities_required")
    ca = public_ca(options.runner_ca_file)
    api_ca = public_ca(options.api_ca_file) if options.api_ca_file else ""
    descriptor_pin = distribution["workload_image_delivery"]
    evidence = "pending-native-qualification:" + descriptor_pin["sha256"]
    template_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "tunnex:sandbox-template:" + org + ":" + descriptor["config_digest"]))
    profile_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "tunnex:sandbox-profile:" + org + ":" + options.source_sha + ":" + descriptor["config_digest"]))
    profile = {"TemplateID": template_id, "ConfigDigest": descriptor["config_digest"], "Architecture": "amd64",
               "PIDs": 64, "QualificationEvidence": evidence}
    binding = {"Admission": "organization", "Mode": "persistent", "OrgID": org, "GatewayID": gateway_id,
               "MemoryMiB": 128, "CPUs": 1, "MaxTTLSeconds": 900, "Profiles": [profile]}
    gateway = {"node_id": gateway_id, "container_id": options.gateway_container_id,
               "image_digest": options.gateway_image_digest, "interface": options.gateway_interface}
    terminal_args = (options.terminal_gateway_node_id, options.terminal_gateway_endpoint, options.runtime_gateway_endpoint)
    need(all(terminal_args) or not any(terminal_args), "all_terminal_gateway_pins_required")
    if all(terminal_args):
        terminal_id = identity(options.terminal_gateway_node_id)
        need(terminal_id != gateway_id, "distinct_terminal_gateway_required")
        terminal_endpoint = endpoint(options.terminal_gateway_endpoint, ipv4=True)
        runtime_endpoint = endpoint(options.runtime_gateway_endpoint, ipv4=True)
        binding["RemoteTerminal"] = {"GatewayID": terminal_id, "GatewayEndpoint": terminal_endpoint,
                                     "RuntimeGatewayEndpoint": runtime_endpoint}
        gateway["terminal"] = {"node_id": terminal_id, "endpoint": terminal_endpoint, "runtime_endpoint": runtime_endpoint}
    else:
        terminal_id = gateway_id
    public_image = urlsplit(descriptor_pin["url"])
    archive_url = urlunsplit(public_image._replace(path=posixpath.join(posixpath.dirname(public_image.path), ARCHIVE)))
    install = {"version": 1, "edition": options.edition, "source_sha": options.source_sha,
               "bundle": distribution["bundles"]["amd64"], "org_id": org, "gateway": gateway,
               "controller": {"url": controller_url, "server_name": server_name, "uri": controller_uri,
                              "api_url": https(options.api_url, True)},
               "images": [{"template_id": template_id, "url": archive_url, "sha256": descriptor["archive"]["sha256"],
                           "config_digest": descriptor["config_digest"], "architecture": "amd64", "qualification_evidence": evidence}]}
    enrollment = {"RunnerURI": runner_uri, "RunnerCA": ca, "APICA": api_ca,
                  "WorkloadImageDelivery": descriptor_pin,
                  "Profile": {"id": profile_id, "name": text(options.profile_name.strip(), 80), "architecture": "amd64",
                              "host_os": "ubuntu", "host_version": "26.04", "terminal_gateway_id": terminal_id,
                              "prerequisites": ["Ubuntu 26.04 AMD64; preinstalled rootless Podman and required host tools",
                                                "systemd 254+, cgroup v2 CPU/memory/PIDs/IO, native overlay and subordinate mappings",
                                                "Exact co-located Docker gateway and private controller connectivity",
                                                "Independent native trial, confirmed cleanup and human review before Ready"],
                              "blocked_reasons": [], "bootstrap_script": distribution["bootstrap_script"], "install": install}}
    remote = {"Listen": listen, "RunnerURI": runner_uri,
              "CertificateFile": reference(options.controller_certificate_file), "PrivateKeyFile": reference(options.controller_private_key_file),
              "CAFile": reference(options.runner_ca_file), "CAKeyFile": reference(options.runner_ca_key_file)}
    return {"Binding": binding, "Remote": remote, "Enrollment": enrollment}


def write_config(output, config):
    path = Path(output)
    need(path.is_absolute() and str(path) == os.path.normpath(str(path)), "absolute_output_required")
    parent = path.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and not parent.st_mode & 0o022,
         "owned_private_output_parent_required")
    raw = (json.dumps(config, indent=2, sort_keys=True) + "\n").encode()
    need(len(raw) <= MAX_CONFIG, "configuration_too_large")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    # Bind the create to the checked directory, including across a rename.
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        current = os.fstat(directory)
        need((current.st_dev, current.st_ino) == (parent.st_dev, parent.st_ino), "changed_output_parent")
        fd = os.open(path.name, flags, 0o600, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink()
        raise


def parser():
    out = argparse.ArgumentParser(description=__doc__)
    for name in ("distribution", "distribution-sha256", "workload-descriptor", "source-sha", "org-id",
                 "gateway-node-id", "gateway-container-id", "gateway-image-digest", "controller-listen", "controller-url",
                 "controller-server-name", "controller-uri", "runner-uri", "api-url", "controller-certificate-file",
                 "controller-private-key-file", "runner-ca-file", "runner-ca-key-file", "output"):
        out.add_argument("--" + name, required=True)
    out.add_argument("--edition", choices=("open", "enterprise"), required=True)
    out.add_argument("--gateway-interface", default="wg0")
    out.add_argument("--profile-name", default="Minimal Ubuntu terminal")
    for name in ("api-ca-file", "terminal-gateway-node-id", "terminal-gateway-endpoint", "runtime-gateway-endpoint"):
        out.add_argument("--" + name)
    return out


def main():
    options = parser().parse_args()
    try:
        write_config(options.output, assemble(options))
    except (OSError, ValueError, TypeError) as error:
        # Inputs are public; avoid reflecting even caller-supplied paths/values.
        reason = str(error) if isinstance(error, Refused) else "public_profile_input_or_output_refused"
        print(reason, file=sys.stderr)
        return 1
    print("Public runner profile written; no enrollment, native qualification, catalog publication or activation performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
