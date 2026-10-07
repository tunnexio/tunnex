import { useRef, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { beamCanOpen, beamLaunchURL, type BeamShare } from "../lib/beam";
import { Button, Modal } from "./ui";

// QR codes carry only the public entry URL. Login handoffs and credentials
// belong to the browser that requested them and must never be shared.
export function beamMobileURL(share: BeamShare, now = Date.now()): string | null {
  if (!beamCanOpen(share, now)) return null;
  const safe = beamLaunchURL(share.url, share.hostname);
  if (!safe) return null;
  const url = new URL(safe);
  return url.pathname === "/" && !url.search && !url.hash ? url.href : null;
}

export function BeamShareMobile({ share, now }: { share: BeamShare; now?: number }) {
  const [open, setOpen] = useState(false);
  const opener = useRef<HTMLElement | null>(null);
  const url = beamMobileURL(share, now);
  if (!url) return null;
  return <><Button variant="ghost" onClick={event => { opener.current = event.currentTarget; setOpen(true); }}>Open on phone</Button>
    {open && <Modal title="Review on your phone" returnFocusTo={opener.current} onDismiss={() => setOpen(false)} actions={<Button variant="ghost" onClick={() => setOpen(false)}>Close</Button>}>
      <div className="space-y-4"><p>Scan this code with your phone camera to open {share.name}.</p>
        <div className="flex justify-center"><QRCodeSVG value={url} size={208} marginSize={4} title={`Preview link for ${share.name}`} /></div>
        <p className="break-all font-mono text-xs">{url}</p>
        <p className="text-sm text-ink-secondary">Sign in on your phone with an account allowed to review this app. No Tunnex app installation is needed. The publisher and local app must remain running.</p>
      </div>
    </Modal>}
  </>;
}
