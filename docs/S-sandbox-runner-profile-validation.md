# Offline enrollment profile validation

The ordinary control-plane configuration path is
`deploy/sandbox/install/profile.py`, documented in its adjacent `PROFILE.md`.
This local implementation started from candidate `b7cc06b3a01d376fa45ab3c0f8a31a145a1316d2`
in isolated branch `story/sandbox-enrollment-profile`. It changes no Go source,
bundle inventory, database, live account, policy, issuer, service or host.

Eight standard-library Python fixtures pass. They check the trusted distribution
hash and source, distribution-to-descriptor checksum, immutable image/config/base
pins and size flags; malformed, duplicate, changed, mutable and symlink inputs;
exact private listener/controller agreement and distinct machine identities;
complete distinct terminal gateway pins; deterministic organization/image
identities; absence of selected creator/terminal or qualification attestations;
and owned mode-0600, collision-refusing output. Instrumented reads include only
the declared public distribution, descriptor and CA certificate. Private-key
references are never opened, and can point at unavailable files in fixtures.
The generated public install plan also passes the actual machine enrollment
translation and installer schema validators. All 43 install/enrollment/profile
fixtures pass together.

A separate source compatibility smoke check generated a synthetic public X.509
CA entirely in memory and produced two public configs: a co-located terminal
gateway and the supported distinct terminal gateway. Both outputs passed the
actual API `LoadAPIWorkerConfig` and `RunnerEnrollmentConfig.Validate` methods.
The temporary validation command was removed after the check. It constructed
no database, issuer, listener, worker or service. The public fixture material
contained no saved user or deployment credentials.

The existing required install tooling check discovers `test_*.py`, including
`test_profile.py`. The generator remains a source deployment tool rather than a
new machine-bundle asset; the current eighteen-public-asset allowlist is unchanged.

The evidence marker is deliberately `pending-native-qualification:<descriptor
SHA256>`. The required field aligns image configuration across the API and
installer; it cannot satisfy the enrollment service's independent native trial,
proof, explicit review and fresh-health gates. These checks demonstrate generated
source configuration compatibility, not a native host qualification, successful
enrollment or activation. Full integrated-source artifact rebuilding, ordinary
deployment configuration and native host qualification remain separate steps.
