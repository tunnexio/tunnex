import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorMessage } from "../lib/api";
import { sandboxPublicKeys } from "../lib/sandboxPublicKeys";
import { Input } from "./ui";
import { Button } from "./ui/button";

type Key = components["schemas"]["SavedSSHKey"];
export function SavedSSHKeyPicker({ orgId, value, onChange }: { orgId: string; value: string; onChange: (value: string) => void }) {
 const [keys, setKeys] = useState<Key[]>([]);
 const [selected, setSelected] = useState<string[]>([]);
 const [manual, setManual] = useState(value);
 const [adding, setAdding] = useState(false);
 const [name, setName] = useState("");
 const [publicKey, setPublicKey] = useState("");
 const [error, setError] = useState("");
 const [busy, setBusy] = useState(false);
 const [loaded, setLoaded] = useState(false);
 const currentManual = useRef(value);
 function publish(items: Key[], ids: string[], text: string) { onChange([...items.filter(k => ids.includes(k.id)).map(k => k.public_key.trim()), text.trim()].filter(Boolean).join("\n")); }
 useEffect(() => { let active = true;
  void api.GET("/api/v1/organizations/{orgId}/saved-ssh-keys", { params: { path: { orgId } } }).then(result => {
   if (!active) return;
   if (!result.data) { setError("Saved keys could not be loaded. You can still paste a public key."); return; }
   const items = result.data.items;
   const lines = currentManual.current.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
   const ids = lines.length ? items.filter(k => lines.includes(k.public_key.trim())).map(k => k.id) : items.filter(k => k.is_default).map(k => k.id);
   const text = lines.filter(line => !items.some(k => ids.includes(k.id) && k.public_key.trim() === line)).join("\n");
   setKeys(items); setSelected(ids); setManual(text); publish(items, ids, text);
  }).catch(() => { if (active) setError("Saved keys could not be loaded. You can still paste a public key."); }).finally(() => { if (active) setLoaded(true); });
  return () => { active = false; };
 }, [orgId]);
 async function save() {
  if (busy) return;
  const parsed = sandboxPublicKeys(publicKey);
  if (!parsed.keys || parsed.keys.length !== 1) { setError("Paste one valid SSH public key from a .pub file. Keep your private key on your computer."); return; }
  setBusy(true); setError("");
  try { const result = await api.POST("/api/v1/organizations/{orgId}/saved-ssh-keys", { params: { path: { orgId } }, body: { name: name.trim(), public_key: parsed.keys[0] } });
   if (!result.data) { setError(apiErrorMessage(result.error, "Key could not be saved. It may already be saved.")); return; }
   const items = [...keys, result.data]; const ids = [...selected, result.data.id]; setKeys(items); setSelected(ids); publish(items, ids, manual); setAdding(false); setName(""); setPublicKey("");
  } catch { setError("Key could not be saved."); } finally { setBusy(false); }
 }
 async function change(key: Key, remove: boolean) {
  if (busy) return; setBusy(true); setError("");
  try {
   const params = { path: { orgId, keyId: key.id } };
   const result = remove ? await api.DELETE("/api/v1/organizations/{orgId}/saved-ssh-keys/{keyId}", { params }) : await api.PUT("/api/v1/organizations/{orgId}/saved-ssh-keys/{keyId}/default", { params });
   if (result.error) { setError(apiErrorMessage(result.error, "Key could not be updated.")); return; }
   const items = remove ? keys.filter(k => k.id !== key.id) : keys.map(k => ({ ...k, is_default: k.id === key.id }));
   const ids = remove ? selected.filter(id => id !== key.id) : selected; setKeys(items); setSelected(ids); publish(items, ids, manual);
  } catch { setError("Key could not be updated."); } finally { setBusy(false); }
 }
 return <fieldset className="space-y-2"><legend className="text-sm font-medium">SSH public keys</legend>
  {!loaded && <p role="status" className="sb-help">Loading saved keys…</p>}
  <div className="max-h-48 overflow-y-auto space-y-2">{keys.map(key => <div key={key.id} className="rounded-lg border border-line p-2 flex items-center gap-2 flex-wrap">
   <label className="flex items-center gap-2 min-w-0 flex-1"><input type="checkbox" disabled={busy} checked={selected.includes(key.id)} onChange={e => { const ids = e.target.checked ? [...selected, key.id] : selected.filter(id => id !== key.id); setSelected(ids); publish(keys, ids, manual); }} /><span className="min-w-0"><strong className="text-sm">{key.name}{key.is_default ? " · Default" : ""}</strong><code className="block text-xs break-all sb-muted">{key.fingerprint}</code></span></label>
   {!key.is_default && <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => void change(key, false)}>Make default</Button>}
   <Button type="button" size="sm" variant="ghost" disabled={busy} aria-label={`Remove ${key.name}`} onClick={() => void change(key, true)}>Remove</Button>
  </div>)}</div>
  <details open={!keys.length}><summary className="text-sm cursor-pointer">Paste public keys</summary><textarea aria-label="SSH public keys" rows={2} maxLength={57350} className="w-full p-2 font-mono text-xs" placeholder="ssh-ed25519 AAAA…" value={manual} onChange={e => { currentManual.current = e.target.value; setManual(e.target.value); publish(keys, selected, e.target.value); }} /></details>
  <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => setAdding(!adding)}>{adding ? "Cancel new key" : "Save a named key"}</Button>
  {adding && <div className="space-y-2 rounded-lg border border-line p-3"><Input aria-label="Key name" maxLength={80} placeholder="Key name" value={name} onChange={e => setName(e.target.value)} /><textarea aria-label="Public key to save" rows={2} maxLength={8192} className="w-full p-2 font-mono text-xs" placeholder="Paste one .pub key" value={publicKey} onChange={e => setPublicKey(e.target.value)} /><Button type="button" size="sm" disabled={busy || !name.trim() || !publicKey.trim()} onClick={() => void save()}>Save & select</Button></div>}
  <p className="sb-help">Public keys only. Removing a saved key leaves existing sandbox access unchanged. Removing the default leaves no default.</p>
  {error && <p role="alert" className="text-sm text-danger">{error}</p>}
 </fieldset>;
}
