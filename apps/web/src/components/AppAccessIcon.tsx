import { useEffect, useState } from "react";
import { Icon, type IconName } from "./Icon";

export const appIconMaxBytes = 64 * 1024;
export const appIconMaxDimension = 512;
const icons: Record<string, IconName> = { app: "monitor", globe: "globe", dashboard: "layout-dashboard", terminal: "terminal" };

export function isAppIconDataURL(value: string): boolean {
  return value.length <= 4 * Math.ceil(appIconMaxBytes / 3) + 23 && /^data:image\/(?:png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$/.test(value);
}

export function AppAccessIcon({ icon, image, className, size = 20 }: { icon: string; image?: string; className?: string; size?: number }) {
  const [failed, setFailed] = useState(false);
  useEffect(() => setFailed(false), [image]);
  return image && isAppIconDataURL(image) && !failed
    ? <img alt="" src={image} width={size} height={size} className={className} style={{ objectFit: "contain" }} referrerPolicy="no-referrer" onError={() => setFailed(true)} />
    : <Icon name={icons[icon] ?? "monitor"} className={className} size={size} />;
}
