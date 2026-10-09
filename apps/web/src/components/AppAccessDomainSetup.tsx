import { useState } from "react";
import { useAuth } from "../lib/auth";
import { AppAccessDomainsSettings } from "./AppAccessDomainsSettings";
import { Button, Modal } from "./ui";
import "../app-access-workspace.css";

export default function AppAccessDomainSetup({ label = "Configure domains" }: { label?: string }) {
  const { state } = useAuth();
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  if (state.status !== "authed" || !state.user.cp_admin) return null;
  return <>
    <Button variant="ghost" className="aa-domain-shortcut" onClick={() => setOpen(true)}>{label}</Button>
    {open && <Modal title="Application domains" placement="right" size="wide" showClose onDismiss={() => { if (!saving) setOpen(false); }}>
      <AppAccessDomainsSettings canEdit={Boolean(state.user.email_verified) && !state.user.must_change_password} onSavingChange={setSaving} onSaved={() => window.dispatchEvent(new Event("app-access-domains-changed"))} />
    </Modal>}
  </>;
}
