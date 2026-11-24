// One way to name a person everywhere a picker and a list refer to the same member (SA-UX-2 item 10):
// "Name (email)", or just the email when there is no distinct name.
export function personLabel(person: { name?: string | null; email?: string | null } | undefined, fallback = "Unknown person"): string {
  const name = person?.name?.trim() ?? "";
  const email = person?.email?.trim() ?? "";
  if (name && email && name.toLowerCase() !== email.toLowerCase()) return `${name} (${email})`;
  return email || name || fallback;
}
