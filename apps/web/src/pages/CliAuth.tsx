import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { useAuth } from "../lib/auth";
import { AuthLayout } from "../components/AuthLayout";
import { Button, ErrorText } from "../components/ui";

// CliAuth is the consent page for `tunnex login` (S5.1). The CLI opens the
// browser here with its loopback redirect_uri + PKCE challenge + state. This
// page is the HUMAN CHECKPOINT (flag-1 acceptance): it NEVER auto-approves —
// minting requires an explicit click — and it DISPLAYS the loopback target
// (host + port) so the user sees which local process is asking. On approve it
// mints the one-time code (cliAuthorize) and redirects the browser to the
// loopback carrying code + state.
export default function CliAuth() {
  const { state: auth } = useAuth();
  const [params] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const redirectUri = params.get("redirect_uri") ?? "";
  const codeChallenge = params.get("code_challenge") ?? "";
  const cliState = params.get("state") ?? "";

  // Parse + sanity-check the loopback target for DISPLAY (the server is the
  // real authority — it re-validates the allowlist on mint).
  let target: URL | null = null;
  try {
    target = new URL(redirectUri);
  } catch {
    /* invalid — handled below */
  }
  const loopbackOk =
    target !== null &&
    target.protocol === "http:" &&
    (target.hostname === "127.0.0.1" ||
      target.hostname === "[::1]" ||
      target.hostname === "::1") &&
    target.port !== "" &&
    target.pathname === "/callback";

  const missing = !redirectUri || !codeChallenge || !cliState;

  async function approve() {
    setBusy(true);
    setError(null);
    const { data, error } = await api.POST("/api/v1/auth/cli/authorize", {
      body: {
        redirect_uri: redirectUri,
        code_challenge: codeChallenge,
        state: cliState,
      },
    });
    if (error || !data) {
      setBusy(false);
      // Minting requires a verified email (requireVerifiedSessionUser). Spell
      // that out instead of a generic failure — the user can act on it.
      if (apiErrorCode(error) === "email_not_verified") {
        return setError(
          "Verify your email before authorizing a device — check your inbox, then try again.",
        );
      }
      return setError(apiErrorMessage(error, "Could not authorize the CLI."));
    }
    // Hand the one-time code back to the CLI's loopback listener.
    const back = new URL(redirectUri);
    back.searchParams.set("code", data.code);
    back.searchParams.set("state", data.state);
    window.location.href = back.toString();
  }

  const email = auth.status === "authed" ? auth.user.email : "";

  return (
    <AuthLayout>
      <h1 className="text-xl font-semibold text-white">
        Authorize the Tunnex CLI
      </h1>
      {missing || !loopbackOk ? (
        <>
          <p className="mt-2 text-sm text-slate-400">
            This link is missing or has an invalid loopback address, so it
            can&rsquo;t be trusted. Re-run{" "}
            <span className="font-mono">tunnex login</span> in your terminal.
          </p>
        </>
      ) : (
        <>
          <p className="mt-2 text-sm text-slate-400">
            Signed in as <span className="text-slate-200">{email}</span>. The
            Tunnex CLI on this machine is requesting a credential. It will be
            delivered only to:
          </p>
          <p className="mt-3 rounded-md border border-white/10 bg-ink-900 px-3 py-2 font-mono text-sm text-white">
            {target!.protocol}//{target!.hostname}:
            <span className="text-accent-400">{target!.port}</span>
            {target!.pathname}
          </p>
          <p className="mt-2 text-xs text-slate-500">
            That is a loopback address on this computer (port {target!.port}).
            If you didn&rsquo;t just run{" "}
            <span className="font-mono">tunnex login</span>, close this page.
          </p>
          <ErrorText>{error}</ErrorText>
          <Button onClick={approve} disabled={busy} className="mt-4 w-full">
            {busy ? "Authorizing…" : "Authorize this CLI"}
          </Button>
        </>
      )}
    </AuthLayout>
  );
}
