import {
  createContext,
  useCallback,
  useContext,
  useState,
  type ReactNode,
} from "react";
import { isUndoable } from "../lib/undo";
import { Button } from "./ui";

// S14.3 SLICE B — TOASTS, AND AN UNDO THAT IS A REAL COMPENSATING ACT.
//
// THREE PROPERTIES, all of which follow from the measured criterion in lib/undo.ts:
//
//  1. UNDO IS A REAL API CALL, AUDITED AS ITS OWN ACT. Never a client-side "put the row back". The audit log
//     must never imply the first act did not happen — it did, and someone may already have acted on it.
//
//  2. UNDO CAN FAIL, AND ITS FAILURE IS LOUD. It is a network call like any other. A silent failure would
//     leave the user believing they reversed something they did not — STRICTLY WORSE THAN THE ORIGINAL
//     MISTAKE, because they have stopped worrying about it. So the failed toast does not auto-dismiss, says
//     what did not happen, and offers a retry.
//
//  3. A TOAST IS NOT A RECORD. It disappears. THE AUDIT LOG IS THE RECORD, and nothing may exist only as a
//     toast.

export type ToastKind = "info" | "error";

export interface Toast {
  id: string;
  kind: ToastKind;
  message: string;
  /** Present only when the originating action passed the undo criterion. */
  undo?: { action: string; run: () => Promise<void> };
  /** Undo lifecycle: offered -> running -> failed. There is no "succeeded" — success dismisses the toast. */
  undoState?: "offered" | "running" | "failed";
}

interface ToastApi {
  /**
   * Show a toast.
   *
   * ⛔ `undo` IS REFUSED unless `action` passes the criterion in lib/undo.ts. Refused LOUDLY in development,
   * and dropped in production rather than rendering a control that cannot keep its promise. A criterion that
   * lives only in prose gets widened one plausible case at a time by people acting in good faith.
   */
  show: (t: {
    kind?: ToastKind;
    message: string;
    action?: string;
    undo?: () => Promise<void>;
  }) => void;
  dismiss: (id: string) => void;
  toasts: Toast[];
}

const ToastContext = createContext<ToastApi | null>(null);

let seq = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback(
    (id: string) => setToasts((ts) => ts.filter((t) => t.id !== id)),
    [],
  );

  const show = useCallback<ToastApi["show"]>(
    ({ kind = "info", message, action, undo }) => {
      const id = `t${++seq}`;
      let entry: Toast = { id, kind, message };
      if (undo) {
        if (!action || !isUndoable(action)) {
          // The offer is dropped, not honoured. An undo control on an act the server cannot reverse is a lie
          // told by a button, and it is worse than no button because the user relies on it.
          if (import.meta.env?.DEV) {
            console.error(
              `[toast] refused an undo for "${action ?? "(no action given)"}": not in UNDOABLE_ACTIONS. ` +
                `An undo requires an inverse operation that returns the SAME OBJECT to its prior state.`,
            );
          }
        } else {
          entry = {
            ...entry,
            undo: { action, run: undo },
            undoState: "offered",
          };
        }
      }
      setToasts((ts) => [...ts, entry]);
    },
    [],
  );

  const runUndo = useCallback(async (t: Toast) => {
    if (!t.undo) return;
    setToasts((ts) =>
      ts.map((x) => (x.id === t.id ? { ...x, undoState: "running" } : x)),
    );
    try {
      await t.undo.run();
      // Success dismisses. The RECORD of both acts is the audit log, not this toast.
      setToasts((ts) => ts.filter((x) => x.id !== t.id));
    } catch {
      // LOUD. Not dismissed, not silent, and the message says what did NOT happen rather than what went wrong
      // — the user needs to know the state of the world, not the shape of the error.
      setToasts((ts) =>
        ts.map((x) =>
          x.id === t.id
            ? {
                ...x,
                kind: "error",
                undoState: "failed",
                message: `Couldn't undo. ${x.message}`,
              }
            : x,
        ),
      );
    }
  }, []);

  return (
    <ToastContext.Provider value={{ show, dismiss, toasts }}>
      {children}
      <ToastList toasts={toasts} onUndo={runUndo} onDismiss={dismiss} />
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  // A no-op rather than a throw: a missing provider must not make a screen unrenderable, and a screen that
  // renders without toasts is degraded, not broken.
  return ctx ?? { show: () => {}, dismiss: () => {}, toasts: [] };
}

function ToastList({
  toasts,
  onUndo,
  onDismiss,
}: {
  toasts: Toast[];
  onUndo: (t: Toast) => void;
  onDismiss: (id: string) => void;
}) {
  if (toasts.length === 0) return null;
  return (
    // `role="status"` + aria-live: a toast nobody announces is a message only sighted users receive.
    // "polite" deliberately — a toast reports something the user just did; interrupting them to say so is
    // worse than waiting for a pause.
    <div
      aria-live="polite"
      className="fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2"
    >
      {toasts.map((t) => (
        <div
          key={t.id}
          role="status"
          className={`rounded-md border px-3 py-2 text-sm ${
            t.kind === "error"
              ? "border-danger/40 bg-ink-800 text-danger"
              : "border-white/10 bg-ink-800 text-slate-300"
          }`}
        >
          <div className="flex items-start justify-between gap-3">
            <span>{t.message}</span>
            <div className="flex shrink-0 items-center gap-1">
              {t.undo && t.undoState !== "running" && (
                <Button variant="ghost" onClick={() => onUndo(t)}>
                  {t.undoState === "failed" ? "Retry undo" : "Undo"}
                </Button>
              )}
              {t.undoState === "running" && (
                <span className="text-xs text-slate-500">Undoing…</span>
              )}
              <Button
                variant="ghost"
                onClick={() => onDismiss(t.id)}
                aria-label="Dismiss"
              >
                ×
              </Button>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
