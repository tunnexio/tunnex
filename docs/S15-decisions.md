# S15 walkthrough security fixes — decisions

This story records the approved walkthrough fixes before product code.

- One-time password reuse: **locked** — forced password change must reject a new password that verifies against the current one-time credential.
- Domain Capture: **locked** — remove shipped UI, runtime auto-membership, and public claim endpoints while retaining historical database rows/schema.
- Microsoft Entra first-save sync: **locked** — make the initial credential/configuration save immediately usable; keep the ten-minute interval plus jitter and make Sync now immediate.
- Entra group removal: **locked** — model access provenance; revoke sessions and active organization access only when no other valid source remains.
- Audit log visibility: **locked** — members retain the page but receive only their own rows; owners/admins receive organization-wide rows. Counts and cursors are server-scoped.
- Google Workspace Directory Sync: **deferred pending product decision** if the existing contract does not specify service-account/domain-wide-delegation identity and administrator subject. Other independent slices continue.
- MFA recovery: **locked** — one-time atomic recovery-code challenge, appropriate session/MFA revocation, fresh enrollment, and strongly authorized/audited administrative reset without secret logging.

No destructive migration is authorized for existing `domain_claim` data.
