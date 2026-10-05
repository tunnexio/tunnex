import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { lazy, Suspense } from "react";
import { DeploymentMetaProvider } from "../src/lib/deploymentMeta";
import { SandboxModuleGate } from "../src/components/SandboxModuleGate";
import { CommandPalette } from "../src/components/CommandPalette";
import type { Meta } from "../src/lib/api";
const apiGet = vi.hoisted(() => vi.fn());
vi.mock("../src/lib/api", () => ({ api: { GET: apiGet } }));
afterEach(cleanup);
const metadata = (state: Meta["sandbox_module_state"]): Meta => ({ edition: "open", protocol_version: 1, sso_providers: [], sandbox_module_state: state });
it.each(["disabled", undefined] as const)("blocks direct routes before lazy import or inventory for %s", async state => {
 const load = vi.fn(async () => ({ default: () => { void apiGet("inventory"); return <div>Sandbox inventory</div>; } }));
 const Page = lazy(load);
 render(<DeploymentMetaProvider value={metadata(state)}><MemoryRouter initialEntries={["/sandboxes/new"]}><Routes><Route element={<SandboxModuleGate />}><Route path="/sandboxes/new" element={<Suspense><Page /></Suspense>} /></Route><Route path="/dashboard" element={<div>Overview</div>} /></Routes></MemoryRouter></DeploymentMetaProvider>);
 await screen.findByText("Overview"); expect(load).not.toHaveBeenCalled(); expect(apiGet).not.toHaveBeenCalled();
});
it.each(["enabled", "draining"] as const)("retains management navigation for %s", async state => {
 render(<DeploymentMetaProvider value={metadata(state)}><MemoryRouter><CommandPalette /></MemoryRouter></DeploymentMetaProvider>);
 fireEvent.keyDown(window, { key: "k", metaKey: true }); expect(screen.getByRole("option", { name: "Sandboxes" })).toBeTruthy();
});
it("hides sandboxes from command palette when deployment is off", () => {
 render(<DeploymentMetaProvider value={metadata("disabled")}><MemoryRouter><CommandPalette /></MemoryRouter></DeploymentMetaProvider>);
 fireEvent.keyDown(window, { key: "k", metaKey: true }); expect(screen.queryByRole("option", { name: "Sandboxes" })).toBeNull(); expect(screen.getByRole("option", { name: "Overview" })).toBeTruthy();
});
it("waits for metadata before mounting a module route", async () => {
 let resolve!: (value: unknown) => void; apiGet.mockReturnValueOnce(new Promise(r => { resolve = r; })); const mounted = vi.fn();
 function Page() { mounted(); return <div>Sandbox management</div>; }
 render(<DeploymentMetaProvider><MemoryRouter initialEntries={["/sandboxes"]}><Routes><Route element={<SandboxModuleGate />}><Route path="/sandboxes" element={<Page />} /></Route><Route path="/dashboard" element={<div>Overview</div>} /></Routes></MemoryRouter></DeploymentMetaProvider>);
 expect(mounted).not.toHaveBeenCalled(); resolve({ data: metadata("enabled") }); await screen.findByText("Sandbox management"); await waitFor(() => expect(apiGet).toHaveBeenCalledTimes(1));
});
