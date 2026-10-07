import { afterEach, describe, expect, it, vi } from "vitest";
import { prepareBeamScreenshot } from "../src/lib/beam-screenshot";
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
describe("Review screenshot preparation", () => {
  it.each([new File(["bad"], "payload.svg", { type: "image/svg+xml" }), new File([], "empty.png", { type: "image/png" }), new File([new Uint8Array(10 * 1024 * 1024 + 1)], "large.jpg", { type: "image/jpeg" })])("rejects unsupported or excessive files before opening them", async file => {
    await expect(prepareBeamScreenshot(file)).rejects.toThrow("PNG or JPEG");
  });
  it("resizes a normal full-screen capture and releases its temporary URL", async () => {
    const create = vi.fn().mockReturnValue("blob:owned"), revoke = vi.fn();
    vi.stubGlobal("URL", { createObjectURL: create, revokeObjectURL: revoke });
    class PreviewImage {
      naturalWidth = 3456; naturalHeight = 2234; onload?: () => void;
      set src(_value: string) { queueMicrotask(() => this.onload?.()); }
    }
    vi.stubGlobal("Image", PreviewImage);
    const draw = vi.fn(), context = { fillStyle: "", fillRect: vi.fn(), drawImage: draw };
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(context as unknown as CanvasRenderingContext2D);
    const sizes: [number, number][] = [];
    vi.spyOn(HTMLCanvasElement.prototype, "toBlob").mockImplementation(function (this: HTMLCanvasElement, callback: BlobCallback) { sizes.push([this.width, this.height]); callback(new Blob(["image-bytes"], { type: "image/jpeg" })); });
    const result = await prepareBeamScreenshot(new File(["owned-image"], "capture.png", { type: "image/png" }));
    expect(result).toBe(btoa("image-bytes")); expect(sizes).toEqual([[1600, 1034]]); expect(draw).toHaveBeenCalled(); expect(revoke).toHaveBeenCalledWith("blob:owned");
  });
  it("releases the temporary URL when image decoding fails", async () => {
    const revoke = vi.fn(); vi.stubGlobal("URL", { createObjectURL: () => "blob:bad", revokeObjectURL: revoke });
    class BadImage { onerror?: () => void; set src(_value: string) { queueMicrotask(() => this.onerror?.()); } }
    vi.stubGlobal("Image", BadImage);
    await expect(prepareBeamScreenshot(new File(["bad"], "bad.png", { type: "image/png" }))).rejects.toThrow("could not be opened");
    expect(revoke).toHaveBeenCalledWith("blob:bad");
  });
});
