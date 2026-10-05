# Historical native qualification fixtures

These fixed qualification units and the supervisor fixture are public regression inputs for the historical Linux AMD64 placement contract. They do not install themselves or qualify a new host. Use the [configurable offline installer](../install/README.md) for current operator-selected identities, paths, trust references and artifact pins.

The generic fixture tests validate transport/actor separation, one224MiB/256-task/zero-swap aggregate, independently bounded synthetic expiry, exact child membership, failure cleanup and refusal behavior. Source tests use synthetic inputs; native execution requires a separately approved isolated host scope. Its units preserve the original UID/GID1101 and subordinate200000:65536 qualification defaults and must never be treated as automatic allocation or installation instructions.

The actor deadline guard freezes/kills the exact UUID-derived128MiB/1CPU/64-PID parent at original expiry. Actor failure kills its entire process tree; transport restart preserves the actor and immutable workload identity. A manager PID change or synthetic freeze/kill pass does not establish provider/network retirement or product Ready.

Run the stdlib-only synthetic checks without installing anything:

```sh
python3 -B -m unittest discover -s deploy/sandbox/qualification -p 'test_*.py'
```

The source fixture can be inspected and tested offline. Do not activate it beside an existing worker, change host protections, manufacture ACKs or reuse historical workload identity. New-host rootless overlay, AppArmor-compatible networking, SSH/SFTP, cgroup behavior, original TTL and full provider/network/file retirement need native qualification within that host's configured limits. Historical evidence and current check results are summarized in [PR validation](../../../docs/S-sandbox-pr-validation.md).
