import { normalizeServerUrl } from "./serverurl";
import { isCanonicalUuid } from "./uuid";

/** The only organization facts that may cross the preload bridge. */
export interface ManagedOrganization {
  id: string;
  name: string;
  slug: string;
  selected: boolean;
}

export interface ManagedOrganizationEnvelope {
  organizations: ManagedOrganization[];
  enrollmentLocked: boolean;
  // Present on the desktop bridge when the lock comes from an unresolved
  // pre-create anchor rather than a completed tunnel record.
  enrollmentRecoveryRequired?: boolean;
  // Occupied by another user; no foreign organization or owner is projected.
  enrollmentBlockedByOtherUser?: boolean;
}

export type LiveOrganization = Pick<ManagedOrganization, "id" | "name" | "slug">;

export interface OrganizationSelectionPersistence {
  get(key: string): string;
  set(key: string, organizationId: string): void;
}

export class NoOrganizationError extends Error {
  constructor() {
    super("no_organization");
    this.name = "NoOrganizationError";
  }
}

export class OrganizationSelectionRequiredError extends Error {
  constructor() {
    super("organization_selection_required");
    this.name = "OrganizationSelectionRequiredError";
  }
}

export class OrganizationSelectionConflictError extends Error {
  constructor() {
    super("remove_managed_device_before_switching_organization");
    this.name = "OrganizationSelectionConflictError";
  }
}

export class OrganizationNotAvailableError extends Error {
  constructor() {
    super("organization_not_available");
    this.name = "OrganizationNotAvailableError";
  }
}

// JSON tuple encoding is collision-free even if a future identity format contains a
// delimiter. Canonicalizing the origin here makes https://cp.example and its trailing-
// slash spelling one selection scope, while a different signed-in user gets another.
export function organizationSelectionKey(origin: string, userId: string): string {
  if (!isCanonicalUuid(userId)) throw new OrganizationNotAvailableError();
  return JSON.stringify([normalizeServerUrl(origin), userId]);
}

function assertLiveOrganizations(live: LiveOrganization[]): void {
  const seen = new Set<string>();
  for (const organization of live) {
    if (!isCanonicalUuid(organization.id) || seen.has(organization.id)) {
      throw new OrganizationNotAvailableError();
    }
    seen.add(organization.id);
  }
}

/**
 * Main-process organization selection policy.
 *
 * Callers supply a FRESH membership list for every operation. The selector persists
 * only an id; an id absent from that live list is never returned as selected. An
 * enrolled device's org takes precedence because moving that credential requires the
 * separate confirmed Remove device flow.
 */
export class ManagedOrganizationSelector {
  constructor(private readonly persistence: OrganizationSelectionPersistence) {}

  organizations(
    origin: string,
    userId: string,
    live: LiveOrganization[],
    enrolledOrganizationId: string | null,
    hasStoredManagedRecord: boolean,
  ): ManagedOrganizationEnvelope {
    if (!isCanonicalUuid(userId)) throw new OrganizationNotAvailableError();
    assertLiveOrganizations(live);
    if (enrolledOrganizationId !== null && !isCanonicalUuid(enrolledOrganizationId)) {
      throw new OrganizationNotAvailableError();
    }
    const selectedId = this.selectedId(
      origin,
      userId,
      live,
      enrolledOrganizationId,
      hasStoredManagedRecord,
    );
    return {
      organizations: live.map((organization) => ({
        ...organization,
        selected: organization.id === selectedId,
      })),
      enrollmentLocked: hasStoredManagedRecord,
    };
  }

  requireFreshEnrollment(
    origin: string,
    userId: string,
    live: LiveOrganization[],
  ): string {
    if (!isCanonicalUuid(userId)) throw new OrganizationNotAvailableError();
    assertLiveOrganizations(live);
    if (live.length === 0) throw new NoOrganizationError();
    const selectedId = this.selectedId(origin, userId, live, null, false);
    if (!selectedId) throw new OrganizationSelectionRequiredError();
    return selectedId;
  }

  select(
    origin: string,
    userId: string,
    live: LiveOrganization[],
    organizationId: string,
    enrolledOrganizationId: string | null,
    hasStoredManagedRecord: boolean,
  ): ManagedOrganizationEnvelope {
    if (!isCanonicalUuid(userId) || !isCanonicalUuid(organizationId)) {
      throw new OrganizationNotAvailableError();
    }
    assertLiveOrganizations(live);
    if (enrolledOrganizationId !== null && !isCanonicalUuid(enrolledOrganizationId)) {
      throw new OrganizationNotAvailableError();
    }
    if (live.length === 0) throw new NoOrganizationError();
    // A stored managed credential is an explicit lock, even when its org is no
    // longer a live membership. Selection never mutates a locked view; Remove
    // device owns the revoke-and-clear transition first.
    if (hasStoredManagedRecord) {
      throw new OrganizationSelectionConflictError();
    }
    if (!live.some((organization) => organization.id === organizationId)) {
      throw new OrganizationNotAvailableError();
    }
    this.persistence.set(organizationSelectionKey(origin, userId), organizationId);
    return this.organizations(
      origin,
      userId,
      live,
      enrolledOrganizationId,
      hasStoredManagedRecord,
    );
  }

  private selectedId(
    origin: string,
    userId: string,
    live: LiveOrganization[],
    enrolledOrganizationId: string | null,
    hasStoredManagedRecord: boolean,
  ): string | null {
    if (hasStoredManagedRecord) {
      // The device binding is display-only for this signed-in user. Never copy
      // another user's stored-device org into this user's enrollment preference.
      // A legacy stored record may have no org at all: that still locks enrollment,
      // but cannot truthfully mark any live organization as its enrolled tenant.
      return enrolledOrganizationId !== null
        && live.some((organization) => organization.id === enrolledOrganizationId)
        ? enrolledOrganizationId
        : null;
    }
    if (live.length === 1) {
      // A sole membership needs no remembered choice. Keep discovery/read paths
      // side-effect free so a later helper teardown refusal cannot still mutate
      // enrollment preference state during proof.
      return live[0].id;
    }
    const saved = this.persistence.get(organizationSelectionKey(origin, userId));
    return live.some((organization) => organization.id === saved) ? saved : null;
  }
}
