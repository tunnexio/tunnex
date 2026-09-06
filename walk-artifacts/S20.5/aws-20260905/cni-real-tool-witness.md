# Local real-tool interoperability witness

2026-09-05 12:02 UTC. This is an isolated Linux primitive proof, **not an
AWS VPN leg**. Container `tunnex-s205-aws-20260905a-nft-witness` used only the
verified task Docker network, NET_ADMIN in its own network namespace, no
host-network mode, no host mounts and no credentials. Its disposable container
was removed normally on exit; no AWS rules or shared host rules were changed.

Runtime base: `alpine:3.20`, pulled manifest digest
`sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`.
This witness resolved aarch64 packages: nftables 1.0.9-r2 and iptables
1.8.10-r3. The separately built final linux/amd64 runtime and real worker
remain required qualification subjects.

Explicit tool readback:

```text
nftables v1.0.9 (Old Doc Yak #3)
iptables-nft-save v1.8.10 (nf_tables)
```

Built an isolated representative AWS chain using the explicit nft-backed
iptables binary, retaining a VPC RETURN and terminal SNAT. Inserted only this
native nft rule at its start:

```text
nft insert rule ip nat AWS-SNAT-CHAIN-0 ip daddr 10.99.0.0/24 oifname "wg0" return comment "tunnex_k8s_aws_snat_bypass"
```

`nft -a -j list chain` returned an ordinary native comment and exactly daddr,
oifname and return expressions. Explicit `iptables-nft-save -t nat` exited 0
with no warning and returned:

```text
-A AWS-SNAT-CHAIN-0 -d 10.99.0.0/24 -o wg0 -m comment --comment tunnex_k8s_aws_snat_bypass -j RETURN
-A AWS-SNAT-CHAIN-0 -d 10.240.0.0/16 -m comment --comment "AWS SNAT CHAIN" -j RETURN
-A AWS-SNAT-CHAIN-0 ! -o vlan+ -m comment --comment "AWS, SNAT" -m addrtype ! --dst-type LOCAL -j SNAT --to-source 10.240.10.204 --random-fully
```

PASS: required packages provide the explicit runtime inspection tool, and a
native owned rule is semantically visible in both readback formats while
foreign rule contents/order are retained. This does not establish packet
delivery, supported hook topology in Docker, authority lifetime, final image
provenance, or AWS controller recovery.
