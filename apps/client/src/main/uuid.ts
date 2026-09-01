// Control-plane identities are generated UUIDs and cross several trust
// boundaries before they become URL path or destructive-operation inputs.
// Accept only the canonical lowercase RFC shape emitted by the API. Supporting
// UUID versions 1-8 keeps the validator compatible with historical v4 and
// current v7 rows while still rejecting dot segments and URL delimiters.
const canonicalUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function isCanonicalUuid(value: unknown): value is string {
  return typeof value === "string" && canonicalUuid.test(value);
}

export function encodeUuidPathSegment(value: unknown, error: string): string {
  if (!isCanonicalUuid(value)) throw new Error(error);
  return encodeURIComponent(value);
}
