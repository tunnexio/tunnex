# Reusable browser SSH target setup

The downloadable `apps/web/public/tunnex-browser-ssh.py` helper supports Ubuntu targets with Python 3, OpenSSH server, and systemd. It configures a dedicated certificate-only listener (default port 2222), leaving management SSH unchanged. Review the script, copy it through a trusted management connection, and install it once:

```sh
sudo install -o root -g root -m 0755 tunnex-browser-ssh.py /usr/local/sbin/tunnex-browser-ssh
```

## First setup of each target

1. Register the server in Tunnex with an enrolled gateway, destination, port and existing Linux accounts. Keep it disabled during setup. To register with an independently verified fingerprint before the helper generates its dedicated host key, use the current management host fingerprint as the initial value; replace it with the dedicated listener fingerprint before enabling/checking.
2. Copy only this installation's public SSH CA from Terminal Settings to `ca.pub` using a trusted management connection. Verify its SHA256 fingerprint independently against the administrator's trusted copy. Never fetch a root script or trust key using an unverified connection or pipe it directly to sudo.
3. Run the generated command from the administrator's server account details:

```sh
sudo tunnex-browser-ssh init --ca ./ca.pub --ca-fingerprint 'SHA256:VERIFIED_CA_FINGERPRINT' --org ORGANIZATION_UUID --server REGISTERED_SERVER_UUID --account ubuntu
```

4. Independently verify the dedicated host fingerprint printed by the helper, save it in Tunnex, allow port 2222 from the selected gateway, run Check while the server is disabled, then enable the server once the account shows Connection checked.
5. Create a bounded user/group account grant. Every connection still requires the grant and recent MFA. No private CA key, application password, MFA seed, or grant is installed by this helper.

## Another Linux account on the same target

Create the Linux account separately according to your normal account-management policy, add it to the registered server's account list, then run:

```sh
sudo tunnex-browser-ssh add-account --account deploy
```

The helper reuses the stored organization/server identity, public CA, dedicated host key and listener. It checks that the CA is unchanged, rejects root/non-login accounts and conflicting principals, preserves existing accounts, validates sshd configuration, and reloads only the listener parent. Changing the account list invalidates Tunnex readiness checks; rerun Check for each account, then grant access. Another Tunnex member using an already configured Linux account needs only their own user/group grant.

## Another target

Install the same reviewed helper on that target and run init with its own registered server UUID. The installation's public CA is reusable; the new target generates its own host key and account principal. Never copy another target's host private key or server identity.

## Inspect or remove

```sh
sudo tunnex-browser-ssh status
sudo tunnex-browser-ssh remove
```

Disable the registered server in Tunnex before removal. Remove stops the dedicated listener and removes only helper-owned files; active browser sessions end. It preserves management SSH and Linux users. It does not delete Tunnex registrations, audit history, recordings or grants. Unmanaged/legacy configurations are refused rather than silently adopted or overwritten. Init refuses existing configuration and an occupied port. A new init generates a new host key: update the verified pinned fingerprint and repeat checks before reconnecting.

## Validation

Run `python3 tests/server-access-setup/test_helper.py` for focused helper safety tests. This helper does not install OS packages, change firewalls, create Linux users, rotate CAs, enroll gateways, grant access or skip MFA/host verification.

## Quick bootstrap: two setup commands

For a new target, Register server with quick bootstrap enabled (default), dedicated port2222 and an initial account. The server starts disabled with pending host trust; it cannot pass SSH checks until the actual independently verified host fingerprint is saved. Open the server's Quick SSH bootstrap section and download its server-specific Python bundle. The authenticated administrator's installation public CA/fingerprint, server UUID and target IP are embedded; no passwords, private keys, MFA seeds or grants are included. Review the downloaded file and transfer it through trusted management SSH (first command), then execute on the registered target (second command):

```sh
sudo python3 tunnex-ssh-bootstrap-SERVER_UUID.py bootstrap --all-login-users
# Alternative selected set:
sudo python3 tunnex-ssh-bootstrap-SERVER_UUID.py bootstrap --accounts ubuntu,deploy
```

Discovery uses the machine's login UID_MIN policy and allowed shells, excludes root, system UIDs, nobody and non-login users, and requires a valid Linux account name. Up to16 accounts are supported; exceeding the limit fails before mutation. Bootstrap checks that the machine owns the registered private IP, refuses different existing server/CA/port bindings and conflicting principals, validates SSH configuration and preserves existing host keys/accounts on reuse. A new server creates a dedicated host key and listener. The helper installs itself for future reuse.

Paste the public result JSON printed between BEGIN/END TUNNEX SSH RESULT into the admin page (or import its setup-result.json file). Verify the fingerprint against the target output, review discovered accounts, and save. This updates the registered account list/fingerprint through normal administrator authorization and revision checks; it never creates grants. Run Check for each account, enable the server, then grant access. Account-list changes require new checks and end sessions using the old configuration.

Later, discover/add another set in one target command:

```sh
sudo tunnex-browser-ssh sync-accounts --all-login-users
# Or:
sudo tunnex-browser-ssh sync-accounts --accounts deploy,appuser
```

Sync is additive: it preserves existing accounts/host keys/CA and does not implicitly remove users or grant access. Review/save the new result in the admin UI. Do not download-and-execute root scripts from an unverified HTTP connection; use the trusted administrator UI and authenticated management SSH transport. The test CP is a scoped HTTP review environment, while production trust/bootstrap delivery requires HTTPS or another independently authenticated source.

## Automatic gateway setup

Register a disabled server using its name, private IP and gateway. Existing accounts can be discovered after registration; this creates no access grants.

1. From trusted management SSH on the target, run `sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256`. Paste only `SHA256:...` into **Verified management SSH fingerprint**. This identifies the existing management listener, separately from the dedicated browser listener.
2. Select management account/port and all eligible login users or a selected set. Click **Prepare automatic setup**; recent administrator MFA is required.
3. Run the generated single authorization command on that target through trusted management SSH. Click **Configure automatically**. No installer SCP or result JSON import is needed.
4. The gateway configures trust and accounts, and the control plane saves the result and queues connection checks. After checks pass, enable the server and grant accounts to users/groups. If check concurrency limits prevent admission, run the remaining checks shown in the UI.

Both management SSH and browser SSH ports must be reachable from the selected gateway. Restrict ingress to its network/security group. Production authorization-command delivery requires authenticated HTTPS; the scoped development deployment uses HTTP for testing.

The job-specific gateway private key exists only in gateway memory. Its target authorized-key entry forces a root-owned launcher, which checks the exact server-bound installer's SHA256 digest before executing it. Shells, forwarding, PTYs and arbitrary commands are refused. The authorization command grants only the exact launcher invocation through a temporary sudoers rule. Execution success or failure removes the job's key, launcher and sudoers rule, preserving unrelated management keys. A transient systemd timer cleans unused authorization at expiry. Authorization lasts at most 15 minutes, additionally bounded by the initiating session and MFA freshness.

Tenant-scoped PostgreSQL jobs retain public material and a sealed initiating-session binding, never gateway private keys. Polling checks logout, user status, membership, administrator role, organization enablement, target revision and gateway certificate authority. Losing polling closes provisioning channels. Server edits/removal invalidate jobs. Gateway restart discards its key and requires a new job; browser refresh restores the latest initiating-admin job. Audit entries contain bounded states, not target output or SSH credentials.

The shared entrypoint detects Linux distribution via `/etc/os-release`. Ubuntu/Debian and RPM-family distributions with Python 3, OpenSSH and systemd pass preflight; Ubuntu 26.04 is the native qualification target. Enforcing SELinux, non-systemd systems, unknown distributions, Windows and macOS are refused before SSH configuration changes. Accepted distributions beyond Ubuntu have not all been natively qualified. Missing packages are not automatically installed and security controls are never disabled. Discovery excludes root, system UIDs and non-login shells; at most 16 accounts are supported. A new Tunnex member only needs a grant. New Linux accounts require another setup/sync and connection checks.

AWS SSM/IAM enrollment is a future provider. The shipped flow here is gateway-assisted SSH with the existing manual/offline fallback.

### Discover accounts created after enrollment

In the admin server details, use **Sync Linux accounts → Sync accounts**.
Keep an enrolled server enabled and enter the independently verified management SSH
fingerprint, and leave **Discover all eligible login users** selected.
Run the newly generated authorization command on that target, then click
**Run account sync**. The gateway reuses this server's existing CA trust,
server identity and browser SSH host key while adding eligible login accounts.
Existing configured accounts and their readiness are retained; existing sessions keep their authority revision. Run Check for new accounts, then grant the new Linux account to users or groups explicitly. Online sync rejects host identity or port changes and removal of existing accounts.
Discovery is manual; creating an OS user does not trigger a periodic sync or
create a Tunnex access grant. Root, system and non-login users are excluded;
the existing limit of 16 configured accounts still applies.
