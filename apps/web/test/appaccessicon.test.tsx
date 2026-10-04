import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import AppAccessIconPicker, { readAppIcon } from "../src/components/AppAccessIconPicker";
import { AppAccessIcon, appIconMaxBytes } from "../src/components/AppAccessIcon";

let dimension = 32;
let invalid = false;
beforeEach(() => {
  dimension = 32; invalid = false;
  vi.stubGlobal("Image", class {
    naturalWidth = dimension; naturalHeight = dimension;
    onload?: () => void; onerror?: () => void;
    set src(_value: string) { queueMicrotask(() => invalid ? this.onerror?.() : this.onload?.()); }
  });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it("rejects active formats, empty/oversized files, unreadable images, and excessive dimensions", async () => {
  await expect(readAppIcon(new File(["<svg/>"], "icon.svg", { type: "image/svg+xml" }))).rejects.toThrow("PNG or JPEG");
  await expect(readAppIcon(new File([], "empty.png", { type: "image/png" }))).rejects.toThrow("64 KiB");
  await expect(readAppIcon(new File([new Uint8Array(appIconMaxBytes + 1)], "big.png", { type: "image/png" }))).rejects.toThrow("64 KiB");
  invalid = true;
  await expect(readAppIcon(new File(["invalid"], "bad.png", { type: "image/png" }))).rejects.toThrow("not a readable");
  invalid = false; dimension = 513;
  await expect(readAppIcon(new File(["image"], "large.png", { type: "image/png" }))).rejects.toThrow("512 × 512");
});

it("previews a chosen image, replaces it, and removes it without losing the default icon", async () => {
  const changed = vi.fn(); const reading = vi.fn();
  function Editor() {
    const [image, setImage] = useState("");
    return <AppAccessIconPicker icon="globe" image={image} onIconChange={vi.fn()} onImageChange={value => { changed(value); setImage(value); }} onReadingChange={reading} />;
  }
  render(<Editor />);
  fireEvent.change(screen.getByLabelText("Upload application icon"), { target: { files: [new File(["first"], "first.png", { type: "image/png" })] } });
  await screen.findByLabelText("Replace application icon");
  expect(changed).toHaveBeenLastCalledWith("data:image/png;base64,Zmlyc3Q=");
  fireEvent.change(screen.getByLabelText("Replace application icon"), { target: { files: [new File(["second"], "second.jpg", { type: "image/jpeg" })] } });
  await waitFor(() => expect(changed).toHaveBeenLastCalledWith("data:image/jpeg;base64,c2Vjb25k"));
  fireEvent.click(screen.getByRole("button", { name: "Remove uploaded icon" }));
  expect(changed).toHaveBeenLastCalledWith("");
  expect(screen.getByLabelText("Default application icon")).toHaveProperty("value", "globe");
  expect(reading).toHaveBeenLastCalledWith(false);
});

it("does not render remote or active image URLs and falls back when raster decoding fails", () => {
  const view = render(<AppAccessIcon icon="globe" image="https://tracking.example/icon.png" />);
  expect(view.container.querySelector("img")).toBeNull();
  view.rerender(<AppAccessIcon icon="globe" image="data:image/svg+xml;base64,PHN2Zy8+" />);
  expect(view.container.querySelector("img")).toBeNull();
  view.rerender(<AppAccessIcon icon="globe" image="data:image/png;base64,YWJj" />);
  fireEvent.error(view.container.querySelector("img")!);
  expect(view.container.querySelector("img")).toBeNull();
  expect(view.container.querySelector("svg")).toBeTruthy();
});

it("releases the editor when leaving the icon step during an unfinished read", async () => {
  vi.stubGlobal("FileReader", class { readAsDataURL() {} });
  function Steps() {
    const [visible, setVisible] = useState(true);
    const [reading, setReading] = useState(false);
    return <><button onClick={() => setVisible(value => !value)}>Switch step</button><button disabled={reading}>Save draft</button>{visible && <AppAccessIconPicker icon="app" onIconChange={vi.fn()} onImageChange={vi.fn()} onReadingChange={setReading} />}</>;
  }
  render(<Steps />);
  fireEvent.change(screen.getByLabelText("Upload application icon"), { target: { files: [new File(["pending"], "icon.png", { type: "image/png" })] } });
  expect(screen.getByRole("button", { name: "Save draft" })).toHaveProperty("disabled", true);
  fireEvent.click(screen.getByRole("button", { name: "Switch step" }));
  expect(screen.getByRole("button", { name: "Save draft" })).toHaveProperty("disabled", false);
  fireEvent.click(screen.getByRole("button", { name: "Switch step" }));
  expect(screen.getByLabelText("Upload application icon")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Save draft" })).toHaveProperty("disabled", false);
});
