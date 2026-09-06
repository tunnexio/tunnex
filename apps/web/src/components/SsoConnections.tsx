import { useEffect, useState } from "react";
import { api, apiErrorMessage } from "../lib/api";
import type { components } from "@tunnex/shared";
import "./sso-connections.css";

type Connection = components["schemas"]["SsoConnection"];
type Draft = components["schemas"]["SsoConnectionRequest"];
export interface SsoConnectionTransport {
  list(org: string): Promise<Connection[]>;
  save(org: string, id: string, draft: Draft): Promise<Connection>;
  test(org: string, id: string, link: boolean): Promise<string>;
  activate(org: string, c: Connection, enabled: boolean): Promise<Connection>;
}
function failure(error: unknown): never {
  throw new Error(
    apiErrorMessage(error, "Could not complete the SSO request. Please retry."),
  );
}
const liveTransport: SsoConnectionTransport = {
  async list(orgId) {
    const { data, error } = await api.GET(
      "/api/v1/organizations/{orgId}/sso-connections",
      { params: { path: { orgId } } },
    );
    if (error || !data) return failure(error);
    return data.items;
  },
  async save(orgId, connectionId, body) {
    const { data, error } = await api.PUT(
      "/api/v1/organizations/{orgId}/sso-connections/{connectionId}",
      { params: { path: { orgId, connectionId } }, body },
    );
    if (error || !data) return failure(error);
    return data;
  },
  async test(orgId, connectionId, link_account) {
    const { data, error } = await api.POST(
      "/api/v1/organizations/{orgId}/sso-connections/{connectionId}/test",
      { params: { path: { orgId, connectionId } }, body: { link_account } },
    );
    if (error || !data) return failure(error);
    return data.redirect_url;
  },
  async activate(orgId, c, enabled) {
    const { data, error } = await api.POST(
      "/api/v1/organizations/{orgId}/sso-connections/{connectionId}/activation",
      {
        params: { path: { orgId, connectionId: c.id } },
        body: { enabled, revision: c.revision },
      },
    );
    if (error || !data) return failure(error);
    return data;
  },
};
export const ssoResultMessages: Record<string, string> = {
  verified: "Sign-in verified. Review the connection below before enabling it.",
  linked:
    "Your company identity is linked. You can use company SSO on your next sign-in.",
  sso_consent_denied:
    "Sign-in was cancelled at the provider. You can retry the test.",
  sso_test_stale:
    "The connection or your session changed during the test. Reload and test again.",
  sso_discovery_failed:
    "The issuer could not be reached. Check its public HTTPS discovery endpoints.",
  sso_verification_failed:
    "The provider response could not be verified. Check the client credentials and required email claims.",
  sso_link_required:
    "The identity could not be linked. Use an identity matching your verified account email.",
  forbidden:
    "Your current account no longer has permission to complete this operation.",
  invalid_state:
    "This sign-in expired, was already used, or belongs to another browser. Start again here.",
  sso_failed:
    "Sign-in could not be completed. Retry, or ask your administrator to check the provider configuration.",
};
const empty: Draft = {
  name: "",
  provider: "okta",
  issuer_url: "",
  client_id: "",
};
export function SsoConnections({
  orgId,
  canEdit,
  transport = liveTransport,
  preview = false,
}: {
  orgId: string;
  canEdit: boolean;
  transport?: SsoConnectionTransport;
  preview?: boolean;
}) {
  const [items, setItems] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState(false);
  const [current, setCurrent] = useState<Connection | null>(null);
  const [draft, setDraft] = useState<Draft>(empty);
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [link, setLink] = useState(false);
  const [notice, setNotice] = useState("");
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    setEditing(false);
    setCurrent(null);
    setDraft(empty);
    transport
      .list(orgId)
      .then((v) => {
        if (!cancelled) {
          setItems(v);
          const params = new URLSearchParams(window.location.search);
          const selected = v.find((c) => c.id === params.get("sso_connection"));
          if (
            selected &&
            params.get("sso_org") === orgId &&
            params.get("sso_test") !== "linked"
          ) {
            setCurrent(selected);
            setDraft({
              name: selected.name,
              provider: selected.provider,
              issuer_url: selected.issuer_url,
              client_id: selected.client_id,
            });
            setStep(selected.verified ? 3 : 2);
            setEditing(true);
          }
        }
      })
      .catch((e) => {
        if (!cancelled) setError(String(e.message));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [orgId, transport]);
  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }
  function retain(c: Connection) {
    setItems((v) => [...v.filter((i) => i.id !== c.id), c]);
    setCurrent(c);
  }
  function open(c?: Connection) {
    setCurrent(c ?? null);
    setDraft(
      c
        ? {
            name: c.name,
            provider: c.provider,
            issuer_url: c.issuer_url,
            client_id: c.client_id,
          }
        : { ...empty },
    );
    setStep(c ? (c.verified ? 3 : 2) : 0);
    setEditing(true);
    setLink(false);
    setError("");
    setNotice("");
  }
  const callback =
    current?.callback_url ??
    `${window.location.origin}/api/v1/auth/sso-connections/callback`;
  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setNotice("Copied to clipboard.");
    } catch {
      setNotice("Select the address and copy it manually.");
    }
  }
  return (
    <section className="sso-workspace" aria-label="Company single sign-on">
      <fieldset disabled={busy} className="sso-request-boundary">
        <header className="sso-heading">
          <div>
            <span className="sso-eyebrow">IDENTITY PROVIDERS</span>
            <h3>Your identity. One secure sign-in.</h3>
            <p>Connect your company’s Okta or OpenID Connect provider.</p>
          </div>
          <button
            disabled={!canEdit || loading || (!!error && !editing)}
            onClick={() => open()}
          >
            ＋ Add connection
          </button>
        </header>
        {preview && (
          <div className="sso-preview-label">
            LOCAL DESIGN PREVIEW · Sample connections. No provider credentials
            are sent.
          </div>
        )}
        {new URLSearchParams(window.location.search).get("sso_test") &&
          new URLSearchParams(window.location.search).get("sso_org") ===
            orgId && (
            <p role="status">
              {ssoResultMessages[
                new URLSearchParams(window.location.search).get("sso_test")!
              ] ?? ssoResultMessages.sso_failed}
            </p>
          )}
        <button
          disabled={loading}
          onClick={() =>
            run(async () => {
              const fresh = await transport.list(orgId);
              setItems(fresh);
              if (current) {
                const updated = fresh.find((c) => c.id === current.id);
                if (updated) {
                  setCurrent(updated);
                  setStep(updated.verified ? 3 : 2);
                }
              }
            })
          }
        >
          Refresh status
        </button>
        {error && (
          <div className="sso-error" role="alert">
            {error}
            <button
              onClick={() =>
                run(async () => setItems(await transport.list(orgId)))
              }
            >
              Retry
            </button>
          </div>
        )}
        {loading ? (
          <p>Loading connections…</p>
        ) : (
          <div className="sso-connection-list">
            {items.map((c) => (
              <div className="sso-connection" key={c.id}>
                <span className={`sso-provider-mark ${c.provider}`}>
                  {c.provider === "okta" ? "O" : "◎"}
                </span>
                <div className="sso-connection-name">
                  <strong>{c.name}</strong>
                  <span>
                    {c.provider === "okta" ? "Okta" : "OpenID Connect"} ·{" "}
                    {c.issuer_url}
                  </span>
                </div>
                <span className={`sso-status ${c.enabled ? "active" : ""}`}>
                  {c.enabled
                    ? "Enabled"
                    : c.verified
                      ? "Verified · disabled"
                      : "Test required"}
                </span>
                <button onClick={() => open(c)}>Manage</button>
              </div>
            ))}
            {items.length === 0 && !error && (
              <p className="sso-empty">
                No custom connections yet. Add a provider to get started.
              </p>
            )}
          </div>
        )}
        {editing && (
          <div className="sso-setup" aria-label="SSO connection setup">
            <header>
              <div>
                <span className="sso-eyebrow">GUIDED SETUP</span>
                <h3>{current?.name ?? "Connect your identity provider"}</h3>
              </div>
              <button
                aria-label="Close setup"
                onClick={() => {
                  setEditing(false);
                  setDraft(empty);
                }}
                disabled={busy}
              >
                ×
              </button>
            </header>
            <ol className="sso-steps">
              {["Provider", "Configure", "Test sign-in", "Enable"].map(
                (s, i) => (
                  <li
                    key={s}
                    className={
                      i === step ? "selected" : i < step ? "complete" : ""
                    }
                  >
                    <span>{i < step ? "✓" : i + 1}</span>
                    {s}
                  </li>
                ),
              )}
            </ol>
            {step === 0 && (
              <>
                <h4>Choose your provider</h4>
                <p>
                  Use a guided Okta setup or connect another standards-based
                  provider.
                </p>
                <div className="sso-provider-choices">
                  {(["okta", "oidc"] as const).map((p) => (
                    <button
                      key={p}
                      className={draft.provider === p ? "chosen" : ""}
                      onClick={() => setDraft((v) => ({ ...v, provider: p }))}
                    >
                      <span className={`sso-provider-mark ${p}`}>
                        {p === "okta" ? "O" : "◎"}
                      </span>
                      <strong>{p === "okta" ? "Okta" : "Generic OIDC"}</strong>
                      <span>
                        {p === "okta"
                          ? "Your workforce identity, connected."
                          : "Bring your own identity provider."}
                      </span>
                    </button>
                  ))}
                </div>
                <footer>
                  <span>
                    Google and Microsoft remain available in Authentication.
                  </span>
                  <button onClick={() => setStep(1)}>Continue →</button>
                </footer>
              </>
            )}
            {step === 1 && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  run(async () => {
                    const c = await transport.save(
                      orgId,
                      current?.id ?? crypto.randomUUID(),
                      draft,
                    );
                    retain(c);
                    setDraft((v) => ({ ...v, client_secret: undefined }));
                    setStep(2);
                  });
                }}
              >
                <h4>
                  Configure{" "}
                  {draft.provider === "okta" ? "Okta" : "OpenID Connect"}
                </h4>
                <p>
                  Create an OIDC web application in your provider and add this
                  exact sign-in redirect URI.
                </p>
                <div className="sso-copy">
                  <code>{callback}</code>
                  <button type="button" onClick={() => copy(callback)}>
                    Copy
                  </button>
                </div>
                <div className="sso-fields">
                  <label>
                    Connection name
                    <input
                      required
                      maxLength={80}
                      placeholder="Acme workforce"
                      value={draft.name}
                      disabled={!canEdit || busy}
                      onChange={(e) =>
                        setDraft((v) => ({ ...v, name: e.target.value }))
                      }
                    />
                  </label>
                  <label>
                    Issuer URL
                    <input
                      required
                      type="url"
                      placeholder={
                        draft.provider === "okta"
                          ? "https://your-company.okta.com"
                          : "https://identity.example.com/realms/company"
                      }
                      value={draft.issuer_url}
                      disabled={!canEdit || busy}
                      onChange={(e) =>
                        setDraft((v) => ({ ...v, issuer_url: e.target.value }))
                      }
                    />
                    <small>
                      Public HTTPS issuer. Endpoints are discovered
                      automatically.
                    </small>
                  </label>
                  <label>
                    Client ID
                    <input
                      required
                      autoComplete="off"
                      value={draft.client_id}
                      disabled={!canEdit || busy}
                      onChange={(e) =>
                        setDraft((v) => ({ ...v, client_id: e.target.value }))
                      }
                    />
                  </label>
                  <label>
                    Client secret
                    <input
                      type="password"
                      autoComplete="new-password"
                      required={!current}
                      placeholder={
                        current
                          ? "Leave blank to keep the saved secret"
                          : "Paste your application secret"
                      }
                      value={draft.client_secret ?? ""}
                      disabled={!canEdit || busy}
                      onChange={(e) =>
                        setDraft((v) => ({
                          ...v,
                          client_secret: e.target.value || undefined,
                        }))
                      }
                    />
                  </label>
                </div>
                <p className="sso-hint">
                  Saving keeps this connection disabled until you test and
                  enable it.
                  {current?.enabled
                    ? " Existing sign-ins through this connection will stop after saving."
                    : ""}
                </p>
                <footer>
                  <button type="button" onClick={() => setStep(0)}>
                    ← Back
                  </button>
                  <button disabled={!canEdit || busy}>
                    {busy ? "Saving…" : "Save and continue →"}
                  </button>
                </footer>
              </form>
            )}
            {step === 2 && current && (
              <>
                <div className="sso-test-symbol">↗</div>
                <h4>Make sure sign-in works.</h4>
                <p>
                  Sign in with your provider. Tunnex will verify the identity
                  and this exact configuration before you can enable it.
                </p>
                <label className="sso-link-choice">
                  <input
                    type="checkbox"
                    checked={link}
                    disabled={!canEdit || busy}
                    onChange={(e) => setLink(e.target.checked)}
                  />
                  Also link this identity to my account. The verified email must
                  match.
                </label>
                <p className="sso-hint">
                  Testing does not enable SSO or replace your current session.
                </p>
                <footer>
                  <button onClick={() => setStep(1)}>
                    ← Edit configuration
                  </button>
                  <button
                    disabled={!canEdit || busy}
                    onClick={() =>
                      run(async () => {
                        const redirect = await transport.test(
                          orgId,
                          current.id,
                          link,
                        );
                        if (preview) {
                          const fresh = await transport.list(orgId);
                          setItems(fresh);
                          setCurrent(
                            fresh.find((c) => c.id === current.id) ?? current,
                          );
                          setStep(3);
                        } else window.location.assign(redirect);
                      })
                    }
                  >
                    {busy
                      ? "Preparing sign-in…"
                      : preview
                        ? "Simulate test sign-in ↗"
                        : "Test sign-in ↗"}
                  </button>
                </footer>
              </>
            )}
            {step === 3 && current && (
              <>
                <div className="sso-test-symbol success">✓</div>
                <h4>
                  {current.enabled
                    ? "Your connection is live."
                    : "Verified. Ready when you are."}
                </h4>
                <p>
                  {preview
                    ? "Simulated verification for local design review."
                    : "The saved configuration passed an OIDC sign-in test."}{" "}
                  Enable it when you’re ready to share company sign-in.
                </p>
                <div className="sso-copy">
                  <code>{current.login_url}</code>
                  <button onClick={() => copy(current.login_url)}>
                    Copy sign-in link
                  </button>
                </div>
                <p className="sso-hint">
                  Password sign-in stays available. Enabling this connection
                  does not enforce SSO.
                </p>
                <footer>
                  <button onClick={() => setStep(1)}>Edit configuration</button>
                  <button
                    disabled={
                      !canEdit ||
                      busy ||
                      (!current.enabled && !current.verified)
                    }
                    onClick={() =>
                      run(async () =>
                        retain(
                          await transport.activate(
                            orgId,
                            current,
                            !current.enabled,
                          ),
                        ),
                      )
                    }
                  >
                    {busy
                      ? "Saving…"
                      : current.enabled
                        ? "Disable connection"
                        : "Enable connection →"}
                  </button>
                </footer>
              </>
            )}
          </div>
        )}
        {notice && <p role="status">{notice}</p>}
      </fieldset>
    </section>
  );
}
