import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

import { api, type Org } from "./api";

// ⛔ THE ORG SEAM (S12.5). It did not exist before this file — and that absence IS the defect.
//
// `GET /api/v1/organizations` returns EVERY organization the caller is a member of. The server has been
// multi-org since S1: `authctx.Principal.Roles` is `map[orgID]role`, rebuilt from the database on every
// single request. The desktop client already uses all of them. **Fourteen web call sites each fetched that
// list themselves and each took index zero** — so a user invited into a second organization could not
// reach it by any means, in ANY edition, licence or no licence.
//
// > ## ⛔ **THEY DID NOT DRIFT TO THE SAME DEFECT BY COPYING. THEY DRIFTED THERE BECAUSE THERE WAS NOWHERE
// > ## ELSE TO GET AN ORG FROM.** A missing seam is not a gap in the code; it is a gap that every future
// > ## call site falls into exactly like the fourteen before it.
//
// ⭐ AND THE SWITCHER IS PROVABLY A VIEW CONCERN, WHICH IS WHY THIS IS SAFE AS WELL AS CHEAP. Selecting an
// org here grants nothing: `authorize()` (http/handlers.go:64) resolves the caller's role from the
// per-request membership query and answers **404 org_not_found** for anything else — before any handler
// runs, and with no oracle. This context can only ever choose among organizations the server would already
// authorize. It cannot choose one it would not.

// ⛔ THE ORG TYPE IS THE GENERATED ONE, RE-EXPORTED — NEVER A HAND-ROLLED SUBSET.
//
// A narrower local shape ({id, name, slug}) compiles and then fails at every call site that already holds
// the full row: `setOrg(first)` on five pages expects `pool_cidr`, `created_at`, `updated_at`. Worse, it
// would have compiled fine anywhere those fields were unused, so the seam would carry a quietly lossy org
// wherever nobody happened to look (docs/laws.md: never hand-sync a generated type).
export type { Org };

type OrgState = {
  /** Every organization the caller belongs to, server-ordered. */
  orgs: Org[];
  /** The organization the UI is acting on. null while loading, or if the caller has none. */
  org: Org | null;
  /** Switch. ⚠ Ignores an id the caller is not a member of — the picker cannot invent a tenant. */
  setOrg: (id: string) => void;
  loading: boolean;
  /** True when the org list could not be read at all. ⚠ NOT the same as "no organizations". */
  failed: boolean;
};

const Ctx = createContext<OrgState | null>(null);

// ⚠ THE SELECTION IS PERSISTED, AND IT IS PERSISTED PER USER-AGENT, NOT PER USER. It is a display
// preference — losing it costs one click and leaking it across profiles is impossible, because a stored id
// the caller is not a member of is discarded on load rather than trusted.
const STORAGE_KEY = "tunnex.currentOrg";

function readStored(): string | null {
  try {
    return window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return null; // private mode / storage disabled — the default org still works
  }
}

function writeStored(id: string) {
  try {
    window.localStorage.setItem(STORAGE_KEY, id);
  } catch {
    /* a switcher that throws because storage is full is worse than one that forgets */
  }
}

export function OrgProvider({ children }: { children: React.ReactNode }) {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [currentId, setCurrentId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .GET("/api/v1/organizations")
      .then(({ data, error }) => {
        if (cancelled) return;
        if (error || !data) {
          setFailed(true);
          setLoading(false);
          return;
        }
        const list = data as Org[];
        setOrgs(list);
        // ⛔ THE STORED ID IS VALIDATED AGAINST MEMBERSHIP, NEVER TRUSTED. A user removed from an org
        // keeps its id in their browser; restoring it blindly would point the whole UI at a tenant whose
        // every request now 404s, which reads as "the app is broken" rather than "you were removed".
        const stored = readStored();
        const restorable =
          stored && list.some((o) => o.id === stored) ? stored : null;
        setCurrentId(restorable ?? list[0]?.id ?? null);
        setLoading(false);
      })
      .catch(() => {
        if (cancelled) return;
        setFailed(true);
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const setOrg = useCallback((id: string) => {
    setOrgs((list) => {
      if (!list.some((o) => o.id === id)) return list; // not a member — ignore, never guess
      setCurrentId(id);
      writeStored(id);
      return list;
    });
  }, []);

  const org = useMemo(
    () => orgs.find((o) => o.id === currentId) ?? null,
    [orgs, currentId],
  );

  const value = useMemo<OrgState>(
    () => ({ orgs, org, setOrg, loading, failed }),
    [orgs, org, setOrg, loading, failed],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/**
 * useOrg is the ONLY supported way for a page to learn which organization it is acting on.
 *
 * ⛔ A page that fetches `/api/v1/organizations` itself is reintroducing the defect this seam exists to
 * remove — not because the fetch is wasteful, but because whatever it picks will not follow the switcher.
 * `test/orgseam.test.tsx` fails the build for exactly that.
 */
export function useOrg(): OrgState {
  const v = useContext(Ctx);
  if (!v) {
    throw new Error("useOrg must be used inside <OrgProvider>");
  }
  return v;
}
