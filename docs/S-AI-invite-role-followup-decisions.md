# Invitation roles and roster simplification — 2026-09-09

User steering: the invite dropdown omits AI roles, and the role-count card is
unnecessary. This follow-up extends the completed navigation/design slice.

## Locked implementation

- Remove the aggregate role-count/summary card from Users and Roles. Keep the
  total people count in the page subtitle and each person's actual role set in
  the roster. Keep last-owner refusal behavior and relevant action guidance.
- Invitations offer every human role the inviter may grant: owner, admin,
  member, ai-admin, ai-view. Reuse the shared human-role list. Only an owner may
  grant owner; AI-only roles do not gain membership-administration permissions.
- Preserve the existing single starting-role invitation contract, expanded to
  the two AI roles end to end. Multiple roles remain assignable through the
  existing role-set editor after the person joins; no new invitation role-set
  storage or machine roles are introduced in this follow-up.
- Expand the invitation database check additively. Existing invitations retain
  their role and token. Accept uses the existing membership-role-set trigger.
  A rollback refuses incompatible AI invitation rows instead of deleting them.
- Resend must preserve the invitation's selected role and continue rotating its
  token. It must not silently turn an AI/administrator invitation into member.
  Creation and resend retain the existing owner-grant boundary with a current
  organization-scoped membership check inside the transaction.

## Verification

Add regression coverage before implementation for AI-role create/accept/resend,
invalid or machine roles, owner-grant restrictions, and the invitation UI.
Regenerate OpenAPI Go/TypeScript and sqlc output. Test/build both API editions,
run relevant database tests only against the identified isolated local preview
stack, and verify the form read-only in the browser. Do not send real invitations
or change existing users' roles. Existing group, model, and credential data is
preserved. No push or merge.
