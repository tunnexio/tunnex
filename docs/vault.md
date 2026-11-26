# Vault

Vault keeps passwords and API keys for your organization's services, encrypted on the control plane, with a
version history for every change. Open it from **Apps & Sharing → Vault**.

> The public documentation site (tunnex-web) needs a matching page; this file is the source for it.

## Who can use it

| Role | What they can do |
| --- | --- |
| Owner, Admin | Everything a member can, plus share credentials with people or groups, edit or move shared credentials, delete them, and add services to the shared list |
| Member | Keep personal credentials; open, copy and save a new secret for credentials shared with them |
| AI Admin, AI Viewer, Operator | No Vault access; the page and its menu entry are hidden |

Everyone also needs a **verified email**. Someone without one sees "Verify your email to use Vault".

## Personal and shared credentials

- **Personal · only you.** Only you can open it or its history. Administrators cannot, and organization audit
  records only that *a* personal credential was used, never its title or service.
- **Assigned · administrators and recipients.** Shared with one person or one group. Recipients and Vault
  administrators can open every version and save a new secret. Only administrators change the title,
  username, service or recipient, or delete it.

The recipient list shows only people who can use Vault. When you pick a group, Vault names any member who
cannot open it yet (no Vault role, or no verified email).

A personal credential cannot be turned into a shared one, or the reverse: that would expose its full history
to new people. To share a personal credential, add it again as Assigned.

## Views

**All**, **Personal**, **Shared with me**, and for administrators **Organization** (every shared credential).

## Adding a credential

- **Add credential** — title, type (password or API key), visibility, service, optional username and the
  secret. Secrets can be up to 16,384 characters.
- **Quick generate** — creates a strong 24-character password. **Save & copy** saves it to your personal
  Vault first, then copies it. It appears as "Generated password · add details"; choose **Add details** to
  give it a title and service (and, for administrators, share it). Adding details does not create a new
  version. Closing without saving asks before discarding.

## Changing a credential

- **Change secret** saves a new version. Earlier versions stay in history and can still be opened.
- **Edit details** changes title, username, service or (for shared credentials) recipient. It does not create
  a version. Moving a shared credential to another recipient gives them every saved version and removes the
  previous recipient's access.

Saving here does not change the password in the external service; update it there too.

## Opening and copying secrets

- Personal credentials open straight away.
- **Shared credentials ask you to confirm it is you**: your current password if your account has one, and a
  two-factor check if you have an authenticator app (valid for 5 minutes in this browser session). An account
  with neither must set up an authenticator first; the page offers it inline.
- Revealed secrets hide after 30 seconds, or when you switch tabs.
- After a copy, Vault clears the clipboard about 30 seconds later **if it still holds that secret**. Some
  browsers (Firefox, or when clipboard reading is refused) do not let a page read the clipboard; then nothing
  is cleared.
- Each person can open or copy at most **30 secrets per minute** in an organization.

## Audit

Every add, change, reveal and copy is in the Audit Log (**Vault activity** filter). Shared credentials are
recorded with their title, service and recipient; personal ones only by type. Secret values and usernames
are never recorded. "Secret copied" records that a copy was requested; the server cannot see a clipboard.

## Leaving an organization

When someone is removed from an organization, or their organization access is revoked by directory sync,
**their personal credentials in that organization are permanently deleted**, with all versions. This is
recorded as "Personal credentials removed with the membership" (a count only). Being invited back does not
restore them. Shared credentials they created stay. Deactivating an account does not delete anything.

## Backups

Vault secrets are sealed with the control plane's master key. A database backup without that key cannot
recover any Vault secret. See [Backup and restore](backup-restore.md).
