import type { BeamAudience, BeamGrant } from "../lib/beam";

// LS-UX-4: `hideUserId` is the publisher. Their own access is implicit (the server adds it), so it is never
// offered as a choice; a grant already present for them stays in `grants` untouched and is saved as is.
export function AudiencePicker({ audience, grants, onChange, disabled, hideUserId }: { audience: BeamAudience; grants: BeamGrant[]; onChange: (grants: BeamGrant[]) => void; disabled: boolean; hideUserId?: string }) {
  const choices = [...audience.users.filter(user => !hideUserId || user.id !== hideUserId).map(user => ({ kind: "user" as const, id: user.id, label: user.name || user.email, detail: user.email })), ...audience.groups.map(group => ({ kind: "group" as const, id: group.id, label: group.name, detail: beamGroupDetail(group.member_count) }))];
  return <div className="beam-picker" role="group" aria-label="Permitted reviewers">{!choices.length && <p className="text-sm">No reviewer choices are currently permitted.</p>}{choices.map(choice => { const selected = grants.some(grant => grant.subject_kind === choice.kind && grant.subject_id === choice.id); return <label key={`${choice.kind}:${choice.id}`}><input type="checkbox" disabled={disabled} checked={selected} onChange={event => onChange(event.target.checked ? [...grants, { subject_kind: choice.kind, subject_id: choice.id }] : grants.filter(grant => grant.subject_kind !== choice.kind || grant.subject_id !== choice.id))} /><span>{choice.label}<span className="block text-xs text-ink-secondary">{choice.detail}</span></span></label>; })}</div>;
}
// LS-UX-3: the server sends a count of current active members (never who they are); older servers omit it.
export function beamGroupDetail(count?: number): string {
  return typeof count === "number" && Number.isFinite(count) && count >= 0 ? `Group · ${count} ${count === 1 ? "member" : "members"}` : "Group";
}
