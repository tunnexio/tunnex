import { Navigate, Outlet } from "react-router-dom";
import { useSandboxModuleState } from "../lib/deploymentMeta";
import { Loading } from "./ui";
export function SandboxModuleGate() {
 const state = useSandboxModuleState();
 if (state === "loading") return <Loading />;
 if (state === "disabled") return <Navigate to="/dashboard" replace />;
 return <Outlet />;
}
