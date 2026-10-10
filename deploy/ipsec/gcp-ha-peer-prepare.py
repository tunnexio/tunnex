#!/usr/bin/env python3
"""Prepare an external emulator from genuine HA material; never grant authority."""
import argparse
import hashlib
import ipaddress
import json
import os
import stat
import unicodedata
import uuid


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate material field")
        out[key] = value
    return out


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_size > 128 * 1024:
            raise ValueError("private bounded material required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(128 * 1024 + 1)
        return json.loads(raw, object_pairs_hook=unique_object)
    finally:
        os.close(fd)


def peer_config(material, peer_gateway_id, generation, local_target, remote_target):
    manifest = material["manifest"]
    if material["kind"] != "apply" or manifest["profile_id"] != "gcp-ha-bgp-ipv4-v1" or manifest.get("bgp_version") != 2 or "transport_version" in manifest or "tunnel_count" in manifest or "recovery_version" in manifest or manifest.get("retained_guard_predecessors"):
        raise ValueError("explicit HA material required")
    compact = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode()
    if hashlib.sha256(compact).hexdigest() != material["ownership_digest"]:
        raise ValueError("genuine canonical material digest mismatch")
    if material["desired_revision"] != manifest["desired_revision"] or material["desired_revision"] <= 0:
        raise ValueError("delivery revision mismatch")
    for field in ["delivery_id"]:
        if uuid.UUID(material[field]).int == 0:
            raise ValueError("nonzero delivery identity required")
    for field in ["org_id", "node_id", "site_id", "connection_id"]:
        if uuid.UUID(manifest[field]).int == 0:
            raise ValueError("nonzero manifest identity required")
    peer_gateway_id = str(uuid.UUID(peer_gateway_id))
    generation = str(uuid.UUID(generation))
    if peer_gateway_id == manifest["node_id"] or uuid.UUID(peer_gateway_id).int == 0 or uuid.UUID(generation).int == 0:
        raise ValueError("distinct external peer identity required")
    local, remote = manifest["remote_prefixes"], manifest["local_prefixes"]
    if len(local) != 1 or len(remote) != 1:
        raise ValueError("single exact approved prefix per direction required")
    local_network, remote_network = ipaddress.IPv4Network(local[0]), ipaddress.IPv4Network(remote[0])
    if local_network.overlaps(remote_network) or local_network.prefixlen == 0 or remote_network.prefixlen == 0:
        raise ValueError("bounded disjoint prefixes required")
    local_target, remote_target = ipaddress.IPv4Address(local_target), ipaddress.IPv4Address(remote_target)
    if local_target not in local_network or remote_target not in remote_network or local_target in [local_network.network_address, local_network.broadcast_address] or remote_target in [remote_network.network_address, remote_network.broadcast_address]:
        raise ValueError("exact approved target endpoints required")
    tunnels, secrets = manifest["tunnels"], material["secrets"]
    if len(tunnels) != 2 or len(secrets) != 2 or tunnels[0]["outside_address"] == tunnels[1]["outside_address"]:
        raise ValueError("two distinct HA outside interfaces required")
    config = {"ProfileID": "gcp-ha-bgp-ipv4-v1", "Scenario": "gcp-ha", "PeerGatewayID": peer_gateway_id, "Generation": generation,
              "GatewayCPAuthority": "real CP only; this standalone peer cannot acknowledge deliveries", "ActivationPerformed": False,
              "LocalTarget": str(local_target), "RemoteTarget": str(remote_target), "CustomTunnels": [], "Interfaces": [], "PSKs": []}
    bgp = manifest["bgp"]
    private_asn = lambda value: type(value) is int and (64512 <= value <= 65534 or 4200000000 <= value <= 4294967294)
    if not private_asn(bgp["local_asn"]) or not private_asn(bgp["remote_asn"]) or bgp["local_asn"] == bgp["remote_asn"] or not 1 <= bgp["maximum_prefixes"] <= 64 or manifest["configuration_revision"] <= 0:
        raise ValueError("bounded distinct private ASN contract required")
    ipaddress.IPv4Address(bgp["router_id"])
    seen_ids, seen_inside = set(), []
    config["BGPConfig"] = {"LocalASN": bgp["remote_asn"], "RemoteASN": bgp["local_asn"], "RouterID": str(local_network.network_address + 1),
                           "MaximumPrefixes": bgp["maximum_prefixes"], "LocalPrefixes": local, "RemotePrefixes": remote, "Peers": []}
    for index, (tunnel, secret) in enumerate(zip(tunnels, secrets)):
        tunnel_id = uuid.UUID(tunnel["id"])
        if tunnel_id.int == 0 or tunnel_id in seen_ids:
            raise ValueError("distinct nonzero tunnel IDs required")
        seen_ids.add(tunnel_id)
        digest = hashlib.sha256(tunnel_id.bytes).digest()
        name, xid = "tx" + digest[:6].hex(), int.from_bytes(digest[:4], "big") | 0x80000000
        if tunnel["slot"] != index + 1 or tunnel["selected"] or tunnel["link_name"] != name or tunnel["xfrm_id"] != xid or tunnel["reqid"] != xid or secret["tunnel_id"] != str(tunnel_id) or secret["revision"] != tunnel["secret_revision"]:
            raise ValueError("exact authenticated tunnel/secret binding required")
        if tunnel["secret_revision"] <= 0 or tunnel["route_table"] != 254 or tunnel["route_protocol"] != 242 or tunnel["route_metric"] != 50001 + index:
            raise ValueError("exact HA route tuple required")
        key = secret["psk"]
        if not isinstance(key, str) or not 8 <= len(key.encode()) <= 64 or not key.strip() or any(unicodedata.category(ch) == "Cc" for ch in key):
            raise ValueError("bounded GCP secret required")
        inside = ipaddress.IPv4Network(tunnel["inside_cidr"])
        customer, cloud = ipaddress.IPv4Address(tunnel["customer_inside_address"]), ipaddress.IPv4Address(tunnel["cloud_inside_address"])
        if inside.prefixlen != 30 or not inside.subnet_of(ipaddress.IPv4Network("169.254.0.0/16")) or customer not in inside or cloud not in inside or customer == cloud or customer in [inside.network_address, inside.broadcast_address] or cloud in [inside.network_address, inside.broadcast_address]:
            raise ValueError("exact HA inside peer pair required")
        if any(inside.overlaps(previous) for previous in seen_inside):
            raise ValueError("distinct HA inside networks required")
        seen_inside.append(inside)
        ipaddress.IPv4Address(tunnel["outside_address"])
        ipaddress.IPv4Address(manifest["customer_outside_address"])
        config["CustomTunnels"].append({"ProfileID": config["ProfileID"], "BGP": True,
            "Binding": {"OrgID": manifest["org_id"], "GatewayID": peer_gateway_id, "ConnectionID": manifest["connection_id"], "DesiredRevision": manifest["desired_revision"], "ConfigurationRevision": manifest["configuration_revision"], "PolicyRevision": 0},
            "TunnelID": str(tunnel_id), "SecretRevision": tunnel["secret_revision"], "XFRMID": xid, "ReqID": xid,
            "LocalAddress": tunnel["outside_address"], "LocalIdentity": tunnel["outside_address"], "RemoteAddress": manifest["customer_outside_address"], "RemoteIdentity": manifest["customer_outside_address"], "LocalPrefixes": local, "RemotePrefixes": remote})
        config["Interfaces"].append({"name": name, "xfrm_id": xid, "alias": "tunnex-ipsec:" + generation + ":" + str(tunnel_id), "address": str(cloud) + "/30", "remote_host_route": str(customer) + "/32", "protocol": 242, "metric": 50001 + index})
        config["BGPConfig"]["Peers"].append({"Slot": index + 1, "LinkName": name, "XFRMID": xid, "Local": str(cloud), "Remote": str(customer)})
        config["PSKs"].append(key)
    return config


def attach_creation_secrets(projection, creation):
    """Use locally supplied creation keys; never extract gateway material secrets."""
    manifest = projection["manifest"]
    if "secrets" in projection or creation["id"] != manifest["connection_id"] or creation["tunnel_ids"] != [t["id"] for t in manifest["tunnels"]]:
        raise ValueError("exact key-free creation binding required")
    supplied = creation["configuration"]
    for field in ["profile_id", "customer_outside_address", "local_prefixes", "remote_prefixes", "bgp"]:
        if supplied[field] != manifest[field]:
            raise ValueError("creation configuration mismatch")
    if len(supplied["tunnels"]) != 2:
        raise ValueError("exact HA creation cardinality required")
    secrets = []
    for actual, original in zip(manifest["tunnels"], supplied["tunnels"]):
        if actual["secret_revision"] != 1:
            raise ValueError("creation keys cannot serve rotated material")
        for field in ["outside_address", "inside_cidr", "customer_inside_address", "cloud_inside_address"]:
            if actual[field] != original[field]:
                raise ValueError("creation tunnel configuration mismatch")
        secrets.append({"tunnel_id": actual["id"], "revision": 1, "psk": original["psk"]})
    return dict(projection, secrets=secrets)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("material")
    parser.add_argument("output")
    parser.add_argument("--creation-request", help="private owned original create input; material argument must be key-free projection")
    parser.add_argument("--peer-gateway-id", required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--local-target", required=True)
    parser.add_argument("--remote-target", required=True)
    args = parser.parse_args()
    material = read_private(args.material)
    if args.creation_request:
        material = attach_creation_secrets(material, read_private(args.creation_request))
    config = peer_config(material, args.peer_gateway_id, args.generation, args.local_target, args.remote_target)
    encoded = json.dumps(config, separators=(",", ":")) + "\n"
    if len(encoded.encode()) > 32 * 1024:
        raise ValueError("bounded peer fixture required")
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(encoded)
    print("Private external-peer config prepared; no API, Docker, lease or journal mutation.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, OverflowError) as error:
        # Never print exception text; a decoder can include supplied secret bytes.
        raise SystemExit("Peer preparation refused; private input/config contract invalid.") from None
