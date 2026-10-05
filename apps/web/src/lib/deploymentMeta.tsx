import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, type Meta } from "./api";

type State = { loaded: boolean; meta: Meta | null };
const Context = createContext<State>({ loaded: true, meta: null });
// Shared with the existing health/version metadata read. No feature endpoint or
// background timer is added; capability changes take effect on page reload.
let request: Promise<Meta | null> | undefined;
export function loadDeploymentMeta() {
 return request ??= api.GET("/api/v1/meta").then(result => result.data ?? null).catch(() => null);
}
export function DeploymentMetaProvider({ children, value }: { children: ReactNode; value?: Meta }) {
 const [state, setState] = useState<State>({ loaded: value !== undefined, meta: value ?? null });
 useEffect(() => {
  if (value !== undefined) { setState({ loaded: true, meta: value }); return; }
  let active = true;
  void loadDeploymentMeta().then(meta => { if (active) setState({ loaded: true, meta }); });
  return () => { active = false; };
 }, [value]);
 return <Context.Provider value={state}>{children}</Context.Provider>;
}
export function useDeploymentMeta() { return useContext(Context); }
export function useSandboxModuleState() {
 const { loaded, meta } = useDeploymentMeta();
 return !loaded ? "loading" : meta?.sandbox_module_state ?? "disabled";
}
