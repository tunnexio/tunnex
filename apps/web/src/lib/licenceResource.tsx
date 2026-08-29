import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  type ReactNode,
} from "react";
import { api, loadOne, type LicenseStatus, type Loaded } from "./api";

type LicenceResource = {
  read: () => Promise<Loaded<LicenseStatus>>;
  publish: (status: LicenseStatus) => void;
};

const LicenceResourceContext = createContext<LicenceResource | null>(null);

/**
 * The licence is deployment-scoped, so the shell and every settings surface must
 * share one answer. Successful reads live for the authenticated app session;
 * installing a key publishes the server response into the same resource.
 */
export function LicenceResourceProvider({ children }: { children: ReactNode }) {
  const cached = useRef<Loaded<LicenseStatus> | null>(null);
  const inflight = useRef<Promise<Loaded<LicenseStatus>> | null>(null);

  const read = useCallback(() => {
    if (cached.current?.ok) return Promise.resolve(cached.current);
    if (inflight.current) return inflight.current;

    const request = loadOne<LicenseStatus>(() => api.GET("/api/v1/license"));
    inflight.current = request;
    void request
      .then((result) => {
        if (result.ok) cached.current = result;
      })
      .finally(() => {
        if (inflight.current === request) inflight.current = null;
      });
    return request;
  }, []);

  const publish = useCallback((status: LicenseStatus) => {
    cached.current = { ok: true, data: status };
  }, []);

  const value = useMemo(() => ({ read, publish }), [publish, read]);
  return (
    <LicenceResourceContext.Provider value={value}>
      {children}
    </LicenceResourceContext.Provider>
  );
}

export function useLicenceResource() {
  return useContext(LicenceResourceContext);
}
