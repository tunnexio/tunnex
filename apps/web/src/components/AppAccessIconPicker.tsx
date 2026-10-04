import { useEffect, useRef, useState } from "react";
import { AppAccessIcon, appIconMaxBytes, appIconMaxDimension, isAppIconDataURL } from "./AppAccessIcon";
import { Button, ErrorText, Field, Input, Select } from "./ui";

type DefaultIcon = "app" | "globe" | "dashboard" | "terminal";

export function readAppIcon(file: File): Promise<string> {
  if (!["image/png", "image/jpeg"].includes(file.type)) return Promise.reject(new Error("Choose a PNG or JPEG image."));
  if (!file.size || file.size > appIconMaxBytes) return Promise.reject(new Error("Choose an image no larger than 64 KiB."));
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Could not read this image. Choose another file."));
    reader.onload = () => {
      const data = reader.result;
      if (typeof data !== "string" || !isAppIconDataURL(data)) { reject(new Error("Choose a valid PNG or JPEG image.")); return; }
      const image = new Image();
      image.onerror = () => reject(new Error("This file is not a readable PNG or JPEG image."));
      image.onload = () => {
        if (!image.naturalWidth || !image.naturalHeight || image.naturalWidth > appIconMaxDimension || image.naturalHeight > appIconMaxDimension) {
          reject(new Error("Choose an image no larger than 512 × 512 pixels.")); return;
        }
        resolve(data);
      };
      image.src = data;
    };
    reader.readAsDataURL(file);
  });
}

export default function AppAccessIconPicker({ icon, image, onIconChange, onImageChange, onReadingChange }: {
  icon: DefaultIcon; image?: string; onIconChange: (value: DefaultIcon) => void;
  onImageChange: (value: string) => void; onReadingChange: (reading: boolean) => void;
}) {
  const [error, setError] = useState("");
  const [reading, setReading] = useState(false);
  const generation = useRef(0);
  useEffect(() => () => { generation.current++; onReadingChange(false); }, [onReadingChange]);
  async function choose(file: File) {
    const request = ++generation.current;
    setError(""); setReading(true); onReadingChange(true);
    try {
      const value = await readAppIcon(file);
      if (request === generation.current) onImageChange(value);
    } catch (failure) {
      if (request === generation.current) setError(failure instanceof Error ? failure.message : "Could not read this image.");
    } finally {
      if (request === generation.current) { setReading(false); onReadingChange(false); }
    }
  }
  return <div className="space-y-3">
    <div className="flex items-center gap-3"><span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-lg border border-line bg-surface"><AppAccessIcon icon={icon} image={image} size={32} /></span><p className="text-sm text-ink-secondary">PNG or JPEG, up to 64 KiB and 512 × 512 pixels. Save to update the icon for everyone with access to this app. No republishing is needed for icon changes.</p></div>
    <Field label={image ? "Replace application icon" : "Upload application icon"}><Input type="file" accept="image/png,image/jpeg" onChange={event => { const file = event.target.files?.[0]; event.target.value = ""; if (file) void choose(file); }} /></Field>
    {reading && <p role="status">Reading application icon…</p>}
    <ErrorText>{error}</ErrorText>
    {image && <Button type="button" variant="ghost" onClick={() => { generation.current++; setReading(false); onReadingChange(false); setError(""); onImageChange(""); }}>Remove uploaded icon</Button>}
    <Field label="Default application icon"><Select value={icon} onChange={event => onIconChange(event.target.value as DefaultIcon)}><option value="app">Application</option><option value="globe">Website</option><option value="dashboard">Dashboard</option><option value="terminal">Terminal</option></Select></Field>
  </div>;
}
