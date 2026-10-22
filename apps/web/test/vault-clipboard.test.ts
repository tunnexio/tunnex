import { afterEach, describe, expect, it, vi } from "vitest";
import { copyVaultPasswordAfterSave } from "../src/lib/vault";

function deferred() {
  let resolve!: () => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<void>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}
class PromisedClipboardItem {
  constructor(readonly data: Record<string, Promise<Blob>>) {}
}
function promisedClipboard(write: (items: PromisedClipboardItem[]) => Promise<void>) {
  vi.stubGlobal("ClipboardItem", PromisedClipboardItem);
  vi.stubGlobal("navigator", { clipboard: { write } });
}
afterEach(() => vi.unstubAllGlobals());

describe("Vault save-before-copy", () => {
  it("reserves the clipboard synchronously but releases the payload only after confirmed persistence", async () => {
    const saving = deferred();
    const copied: string[] = [];
    const write = vi.fn(async ([item]: PromisedClipboardItem[]) => { copied.push(await (await item.data["text/plain"]).text()); });
    promisedClipboard(write);
    const copy = copyVaultPasswordAfterSave("SyntheticPassword!234", () => saving.promise, () => true);
    expect(write).toHaveBeenCalledTimes(1);
    await Promise.resolve();
    expect(copied).toEqual([]);
    saving.resolve();
    await copy;
    expect(copied).toEqual(["SyntheticPassword!234"]);
  });

  it("rejects the promised payload when persistence fails", async () => {
    const saving = deferred();
    const copied: string[] = [];
    const write = vi.fn(async ([item]: PromisedClipboardItem[]) => { copied.push(await (await item.data["text/plain"]).text()); });
    promisedClipboard(write);
    const copy = copyVaultPasswordAfterSave("SyntheticPassword!234", () => saving.promise, () => true);
    saving.reject(new Error("private persistence diagnostic"));
    await expect(copy).rejects.toMatchObject({ reason: "save_failed" });
    expect(copied).toEqual([]);
  });

  it("withholds the payload if the drawer or identity boundary is no longer current", async () => {
    const saving = deferred();
    let current = true;
    const copied: string[] = [];
    promisedClipboard(async ([item]) => { copied.push(await (await item.data["text/plain"]).text()); });
    const copy = copyVaultPasswordAfterSave("SyntheticPassword!234", () => saving.promise, () => current);
    current = false;
    saving.resolve();
    await expect(copy).rejects.toMatchObject({ reason: "cancelled" });
    expect(copied).toEqual([]);
  });

  it("waits for the save outcome even if clipboard permission is refused immediately", async () => {
    const saving = deferred();
    let settled = false;
    promisedClipboard(() => Promise.reject(new Error("permission refused")));
    const copy = copyVaultPasswordAfterSave("SyntheticPassword!234", () => saving.promise, () => true);
    void copy.then(() => { settled = true; }, () => { settled = true; });
    await Promise.resolve();
    await Promise.resolve();
    expect(settled).toBe(false);
    saving.resolve();
    await expect(copy).rejects.toMatchObject({ reason: "copy_failed" });
  });

  it("copies a confirmed saved-row retry during the click without starting another save", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("ClipboardItem", undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const copy = copyVaultPasswordAfterSave("SyntheticPassword!234", undefined, () => true);
    expect(writeText).toHaveBeenCalledWith("SyntheticPassword!234");
    await copy;
  });

  it("does not use the fallback clipboard if saving fails or the context is cancelled", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("ClipboardItem", undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    await expect(copyVaultPasswordAfterSave("SyntheticPassword!234", () => Promise.reject(new Error("save failed")), () => true)).rejects.toMatchObject({ reason: "save_failed" });
    await expect(copyVaultPasswordAfterSave("SyntheticPassword!234", () => Promise.resolve(), () => false)).rejects.toMatchObject({ reason: "cancelled" });
    expect(writeText).not.toHaveBeenCalled();
  });
});
