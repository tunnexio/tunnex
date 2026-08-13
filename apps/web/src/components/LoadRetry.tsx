// LoadRetry — the shared "a load FAILED, here is a legible retry" affordance (S7.4a no-false-empty
// discipline). Extracted from the byte-identical copies Access + Sites carried (review #7) so a styling
// or a11y fix lands in one place. A transient API error must be legible + retryable, never rendered as
// "none / not an admin".
export function LoadRetry({
  error,
  onRetry,
}: {
  error: string;
  onRetry: () => void;
}) {
  return (
    <div className="mt-2 rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-xs text-amber-300">
      {error}{" "}
      <button
        className="underline underline-offset-2 hover:text-amber-200"
        onClick={onRetry}
      >
        Retry
      </button>
    </div>
  );
}
