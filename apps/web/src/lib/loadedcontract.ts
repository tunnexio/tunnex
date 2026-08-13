import type { Loaded } from "./api";

// THE `Loaded<T>` CONTRACT, ASSERTED MECHANICALLY — because a standard recorded only in prose is the
// convention-not-mechanism failure this project keeps finding (branch protection is the precedent).
//
// WHY THIS FILE EXISTS. `loadOne`'s law is that a failed load must never render as an empty or a defaulted
// value. On the Access screen the defaulted value would be "0 rules — ALL traffic denied." on a load that never
// returned — an authorization claim invented by the client.
//
// That law is currently enforced BY THE TYPE, not by discipline: `Loaded<T>` is a discriminated union, so
// `.data` is unreachable without narrowing `.ok`. A mutation that drops the `.ok` check does not produce a
// wrong render — it produces a COMPILE ERROR. (Found by trying to break it: docs/laws.md, "A GUARD ENFORCED BY
// TYPES BEATS ONE ENFORCED BY DISCIPLINE".)
//
// THE RISK THIS FILE CLOSES. Widening the union to `{ ok: boolean; data?: T; error?: string }` — the shape a
// hurried refactor reaches for, because it is easier to construct — silently converts that compile-time
// guarantee into a discipline nobody audits. NOTHING FAILS when it happens. No test goes red. The guard simply
// stops existing, and its absence looks like ordinary code. That is the silent-guard-removal class.
//
// IT LIVES IN `src/` DELIBERATELY. `tsconfig.json` includes only `src`, so `tsc --noEmit` — the gate behind
// `pnpm --filter @tunnex/web typecheck` — does NOT typecheck `test/`. A contract assertion placed there would
// never be evaluated by any gate, which would be a check that cannot fail.

/** Expect<T> fails to compile unless T is exactly `true`. */
type Expect<T extends true> = T;
type IsNever<T> = [T] extends [never] ? true : false;
type Not<T extends boolean> = T extends true ? false : true;

type OkBranch = Extract<Loaded<number>, { ok: true }>;
type ErrBranch = Extract<Loaded<number>, { ok: false }>;

// 1 + 2 — THE UNION MUST ACTUALLY DISCRIMINATE. Under the widened shape `{ ok: boolean; … }`, neither
// `Extract` can match (`boolean` is not assignable to `true` or to `false`), so BOTH branches collapse to
// `never` and these two assertions fail. This is the check that catches the widening.
export type _LoadedHasOkBranch = Expect<Not<IsNever<OkBranch>>>;
export type _LoadedHasErrBranch = Expect<Not<IsNever<ErrBranch>>>;

// 3 — THE FAILURE BRANCH MUST CARRY NO `data` AT ALL. Not "optional data" — none. An optional `data` on the
// error branch is precisely what lets a failed load supply a defaulted value.
export type _LoadedErrBranchHasNoData = Expect<
  "data" extends keyof ErrBranch ? false : true
>;

// 4 — `data` MUST BE REQUIRED ON THE SUCCESS BRANCH. If it were optional, `ok: true` would no longer
// guarantee a value and every consumer would need a second check that nothing forces them to write.
export type _LoadedOkDataIsRequired = Expect<
  undefined extends OkBranch["data"] ? false : true
>;
