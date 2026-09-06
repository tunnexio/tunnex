import { useEffect, useState } from "react";
import { api, apiErrorMessage } from "../lib/api";
import type { components } from "@tunnex/shared";
import { ssoResultMessages } from "./SsoConnections";
export function SsoSelfLink({ orgId }: { orgId: string }) {
  const [items, setItems] = useState<components["schemas"]["SsoConnection"][]>(
    [],
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let gone = false;
    api
      .GET("/api/v1/organizations/{orgId}/sso-connections/available", {
        params: { path: { orgId } },
      })
      .then(({ data, error }) => {
        if (gone) return;
        if (error) {
          setError(
            apiErrorMessage(
              error,
              "Company sign-in links could not be loaded.",
            ),
          );
          return;
        }
        setItems(data?.items ?? []);
      })
      .catch(() => {
        if (!gone) setError("Company sign-in links could not be loaded.");
      });
    return () => {
      gone = true;
    };
  }, [orgId]);
  const query = new URLSearchParams(window.location.search);
  const result = query.get("sso_test");
  if (!items.length && !error && !(result && query.get("sso_org") === orgId))
    return null;
  return (
    <section className="sso-workspace" aria-label="Link company sign-in">
      <h3>Link company sign-in</h3>
      <p>
        Keep your existing account and connect your company identity. Sign in
        with the same verified email address.
      </p>
      {result && query.get("sso_org") === orgId && (
        <p role="status">
          {ssoResultMessages[result] ?? ssoResultMessages.sso_failed}
        </p>
      )}
      {error && <p role="alert">{error}</p>}
      {items.map((c) => (
        <div className="sso-connection" key={c.id}>
          <div className="sso-connection-name">
            <strong>{c.name}</strong>
            <span>{c.issuer_url}</span>
          </div>
          <button
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setError("");
              try {
                const { data, error } = await api.POST(
                  "/api/v1/organizations/{orgId}/sso-connections/{connectionId}/link",
                  { params: { path: { orgId, connectionId: c.id } } },
                );
                if (error || !data)
                  throw new Error(
                    apiErrorMessage(error, "Could not start identity linking."),
                  );
                window.location.assign(data.redirect_url);
              } catch (e) {
                setError(
                  e instanceof Error ? e.message : "Could not link identity",
                );
                setBusy(false);
              }
            }}
          >
            Link my account ↗
          </button>
        </div>
      ))}
    </section>
  );
}
