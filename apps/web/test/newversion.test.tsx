import { afterEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { entryScript, newerBuildAvailable } from "../src/lib/newVersion";
import { NewVersionBanner } from "../src/components/NewVersionBanner";
afterEach(cleanup);

const page = (src: string) => `<!doctype html><html><head><script type="module" crossorigin src="${src}"></script></head></html>`;
const served = (html: string, ok = true) => vi.fn(async () => ({ ok, text: async () => html }) as unknown as Response);

it("reads the entry script from an index document", () => {
  expect(entryScript(page("/assets/index-new.js"))).toBe("/assets/index-new.js");
  expect(entryScript("<html></html>")).toBeNull();
});
it("reports a newer build only when the served entry differs from the loaded one (SA-UX-2 item 7)", async () => {
  expect(await newerBuildAvailable(served(page("/assets/index-new.js")), "/assets/index-old.js")).toBe(true);
  expect(await newerBuildAvailable(served(page("/assets/index-old.js")), "/assets/index-old.js")).toBe(false);
  expect(await newerBuildAvailable(served("", false), "/assets/index-old.js")).toBe(false);
  expect(await newerBuildAvailable(vi.fn(async () => { throw new Error("offline"); }), "/assets/index-old.js")).toBe(false);
  // The Vite dev server loads /src/main.tsx: no check.
  const fetcher = served(page("/assets/index-new.js"));
  expect(await newerBuildAvailable(fetcher, "/src/main.tsx")).toBe(false);
  expect(fetcher).not.toHaveBeenCalled();
});
it("asks only its own origin", async () => {
  const fetcher = served(page("/assets/index-old.js"));
  await newerBuildAvailable(fetcher, "/assets/index-old.js");
  expect(fetcher).toHaveBeenCalledWith("/index.html", expect.objectContaining({ cache: "no-store", credentials: "same-origin" }));
});
it("shows a non-blocking banner and reloads only on request", async () => {
  const reload = vi.fn();
  await act(async () => { render(<NewVersionBanner check={async () => true} reload={reload} />); });
  expect(screen.getByText(/A new version of Tunnex is available/)).toBeTruthy();
  expect(reload).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Reload" }));
  expect(reload).toHaveBeenCalledOnce();
});
it("stays hidden when there is no newer build", async () => {
  await act(async () => { render(<NewVersionBanner check={async () => false} />); });
  expect(screen.queryByText(/A new version/)).toBeNull();
});
