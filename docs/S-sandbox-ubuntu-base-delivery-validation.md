# Ubuntu dependency and archive delivery validation

Source content tip: `4fd7c533bab3f091633fdeca96d6bff21e273d7f` on
`story/sandbox-ubuntu-base-delivery`, based on candidate `b7e984c`. This is a local
build validation, not native runner qualification or a published release.

The real Docker Official Ubuntu26 AMD64 base manifest is
`sha256:88a381d5b5eeb2b35d3ad70925a362c37ce569daf43ede89ff818ec20e4d3794`.
The dependency lock SHA256 is
`9f94996bd8b3969daac310e57cdf3c6fa36b3e96f534af08a3ec6d50aa494512`.
APT authenticated all three official `20261001T000000Z` snapshot pockets with
the pinned base's Ubuntu keyring, then selected 55 downloads against nine signed
metadata/index files. The completed image has 142 installed packages, exactly
matching its locked inventory. The package downloads total 19,567,904 bytes;
metadata/index inputs total 19,585,173 bytes. Registry preparation used an empty
temporary auth configuration; no operator credential input was needed.

The actual source-pinned Docker BuildKit build passed on the local Linux build
engine using AMD64 emulation. Package installation and final assembly had
`network=none`, with the pinned base already local and pulls disabled. A
read-only build-context mount avoids retaining downloaded `.deb` files in image
layers. `policy-rc.d` inhibited package service starts; generated SSH host keys
were removed in the same install layer. Build checks verified standard
WireGuard/ip/SSH/SFTP/Python/SSL/resolvconf/setpriv/nft paths and uid1001. No
workload/runner was started or machine enrolled.

| Output | Verified value |
| --- | --- |
| Archive | `tunnex-sandbox-ubuntu26-linux-amd64.docker.tar` |
| Archive bytes | 71,403,520 (68.10 MiB) |
| Archive SHA256 | `329e1ccb06013e66fcb2f28cecbc304ff1d236f4dfdf7ea4045a82410a9648f8` |
| Immutable config digest | `sha256:2e592dff9cec9ec1c92372f126ecac7362241bcb2c0399a7ac80c78a3f7a0cb6` |
| Verified uncompressed layer bytes | 195,198,976 (186.16 MiB) |
| Native qualification | false |

`archive.verify_delivery` passed on the complete three-file output: Docker
archive, `workload-image.json`, and bare-filename `SHA256SUMS`. It checked exact
source/lock labels, uid1001/workspace, architecture, archive/config hashes and
every layer's uncompressed diff ID. Docker29's containerd store reports an OCI
index ID and compressed image size; the producer derives the config identity
and uncompressed size from the archive instead. Earlier real assembly attempts
also exposed APT's exact cache basename/epoch and read-only partial-directory
requirements. Those were corrected without changing package versions/hashes or
enabling network installation.

The 17 new source/fixture tests and three existing Ubuntu final-layer recipe
fixtures passed. They cover corrupt caches/archives, mutable/missing inputs,
unknown credential-shaped fields, public anonymous registry operations, strict
context inventory, nonroot image identity, source/lock/layer pin drift, and
invented size/qualification claims. These checks do not substitute for native
AppArmor, WireGuard handshake, private terminal SSH, cgroup deadlines, offline
revocation, cleanup or latency/resource tests on the enrolled Linux host.

The measured image is within the proposed 250 MB unpacked budget. Idle memory
and startup latency were not measured for this image. ARM64 activation remains
unavailable. No publication, live activation or trust promotion occurred, and
byte-identical two-build OCI output has not been established. Release delivery
must rebuild and verify artifacts against the final integrated source SHA.
