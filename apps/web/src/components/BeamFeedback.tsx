import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { beamRoomsApi, beamScreenshotURL, type BeamFeedback as Feedback, type BeamFeedbackInput, type BeamNotification } from "../lib/beam-rooms";
import { beamIsTerminal, beamNeedsMfa, type BeamPage, type BeamShare, type BeamViewer } from "../lib/beam";
import { personLabel } from "../lib/personLabel";
import { useBeamClock } from "../lib/beam-clock";
import { prepareBeamScreenshot } from "../lib/beam-screenshot";
import { Button, ErrorText, Field, Loading, Modal, RefreshButton } from "./ui";
import { Pagination } from "./BeamRooms";
import { Icon } from "./Icon";
import AppAccessEmptyState from "./AppAccessEmptyState";
import { InlineTerminalMfa } from "./InlineTerminalMfa";
// The server keeps a Local Sharing MFA check fresh for 5 minutes (internal/beam/authority.go).
const BEAM_MFA_FRESHNESS_SECONDS = 300;
/** LS-UX-3: a policy MFA check explained in neutral words, with the console's inline step-up behind one button. */
function BeamMfaPrompt({ reason, action, verifying, onVerify, onVerified, onCancel }: { reason: string; action: string; verifying: boolean; onVerify: () => void; onVerified: () => void | Promise<void>; onCancel: () => void }) {
  return <div className="beam-mfa-prompt space-y-3">{verifying
    ? <InlineTerminalMfa action={action} freshnessSeconds={BEAM_MFA_FRESHNESS_SECONDS} onVerified={onVerified} onCancel={onCancel} />
    : <><p className="text-sm text-ink-secondary">{reason}</p><Button type="button" data-beam-feedback-focus onClick={onVerify}><Icon name="shield-check" size={14} />Verify MFA</Button></>}</div>;
}
const decisions: { value: BeamFeedbackInput["status"]; label: string; meaning: string }[] = [
  { value: "comment", label: "Comment", meaning: "A note without a decision." },
  { value: "approved", label: "Approve", meaning: "Tell the publisher it looks good." },
  { value: "changes_requested", label: "Request changes", meaning: "Ask the publisher to change something." },
];
const decisionLabel: Record<string, string> = { comment: "Comment", approved: "Approved", changes_requested: "Changes requested" };
export function BeamFeedback({ orgId, share, uncertain = false, viewer = "publisher" }: { orgId: string; share: BeamShare; uncertain?: boolean; viewer?: BeamViewer }) {
  const [data, setData] = useState<BeamPage<Feedback> | null>(null); const [error, setError] = useState(""); const [closed, setClosed] = useState(""); const [notice, setNotice] = useState(""); const [reload, setReload] = useState(0); const [page, setPage] = useState(0); const [pageSize, setPageSize] = useState(20);
  const [body, setBody] = useState(""); const [status, setStatus] = useState<BeamFeedbackInput["status"]>("comment"); const [screenshot, setScreenshot] = useState(""); const [fileName, setFileName] = useState(""); const [reading, setReading] = useState(false); const [busy, setBusy] = useState(false); const [writeUncertain, setWriteUncertain] = useState(false);
  // "read": the feedback could not be loaded until MFA is verified; "send": a draft is waiting for it.
  const [mfa, setMfa] = useState<"" | "read" | "send">(""); const [verifying, setVerifying] = useState(false);
  const clock = useBeamClock();
  const [, tick] = useState(0);
  useEffect(() => { const timer = window.setInterval(() => tick(n => n + 1), 1000); return () => window.clearInterval(timer); }, []);
  const alive = useRef(true); const lock = useRef(false); const upload = useRef(0); const fileInput = useRef<HTMLInputElement | null>(null);
  useEffect(() => { alive.current = true; return () => { alive.current = false; upload.current += 1; }; }, []);
  const publisher = viewer === "publisher";
  // LS-UX-2: the review room closes when a share ends; only its publisher keeps the history.
  const endedForReviewer = !publisher && beamIsTerminal(share, clock.now());
  useEffect(() => { let current = true; setData(null); setError(""); setClosed(""); if (uncertain) return; if (endedForReviewer) { setClosed("Feedback closed when this share ended."); return; } void beamRoomsApi.feedback(orgId, share.id, page * pageSize, pageSize).then(result => { if (!current) return; if (result.ok) { clock.synchronize(result.data.server_time ?? result.server_time); setData(result.data); setWriteUncertain(false); setMfa(current => current === "read" ? "" : current); } else if (beamNeedsMfa(result.code)) setMfa("read"); else if (!publisher && result.code === "beam_share_not_found") setClosed(viewer === "manager" ? "Feedback is visible to the publisher and the share's reviewers." : "Feedback is not available to your account right now. Refresh the share to check your access."); else setError(result.error); }); return () => { current = false; }; }, [orgId, share.id, share.authority_version, share.state, uncertain, reload, page, pageSize, endedForReviewer]);
  const canWrite = Boolean(data) && !beamIsTerminal(share, clock.now()) && !uncertain && !writeUncertain;
  const sendable = Boolean(body.trim() || status !== "comment" || screenshot);
  function clearAttachment() { upload.current += 1; setScreenshot(""); setFileName(""); setReading(false); if (fileInput.current) fileInput.current.value = ""; }
  async function attachment(file?: File) {
    const sequence = ++upload.current; setScreenshot(""); setFileName(""); setError(""); setReading(false); if (!file) return;
    setReading(true); setFileName(file.name);
    try { const raw = await prepareBeamScreenshot(file); if (alive.current && upload.current === sequence) { setScreenshot(raw); setReading(false); } }
    catch (error) { if (alive.current && upload.current === sequence) { setReading(false); setFileName(""); setError(error instanceof Error ? error.message : "Could not prepare the screenshot. Choose the file again."); if (fileInput.current) fileInput.current.value = ""; } }
  }
  function submit(event: React.FormEvent) { event.preventDefault(); void send(); }
  async function send() {
    if (!canWrite || lock.current || reading || !sendable) return;
    lock.current = true; setBusy(true); setError(""); setNotice("");
    try { const result = await beamRoomsApi.addFeedback(orgId, share.id, { body: body.trim(), status, ...(screenshot ? { screenshot_base64: screenshot } : {}) }); if (!alive.current) return;
      if (result.ok) { setMfa(""); setBody(""); clearAttachment(); setStatus("comment"); setNotice(publisher ? "Feedback sent. Reviewers see it on this page." : "Feedback sent. The publisher sees it on this page and in Sharing updates."); setPage(0); setReload(n => n + 1); }
      // The server checks MFA before it writes anything, so the draft is safe to send again after verifying.
      else if (beamNeedsMfa(result.code)) { setMfa("send"); setVerifying(true); }
      else { setError(`${result.error} Refresh feedback before submitting again; your draft is still shown.`); setWriteUncertain(true); }
    } finally { lock.current = false; if (alive.current) setBusy(false); }
  }
  const form = canWrite ? <form onSubmit={event => void submit(event)} className="beam-feedback-form space-y-4" aria-label="Send review feedback">
    <fieldset className="beam-decision" disabled={busy}><legend>Review decision</legend><div className="beam-decision-options">{decisions.map(option => <label key={option.value} className="beam-decision-option" data-selected={status === option.value || undefined}><input type="radio" name={`beam-decision-${share.id}`} value={option.value} checked={status === option.value} onChange={() => setStatus(option.value)} /><span><strong>{option.label}</strong><span>{option.meaning}</span></span></label>)}</div></fieldset>
    <Field label="Your feedback"><textarea maxLength={4000} rows={4} value={body} disabled={busy} onChange={event => setBody(event.target.value)} className="w-full rounded border border-line bg-surface p-3" placeholder="What worked, or what should change?" /></Field>
    <div className="beam-attachment space-y-2"><span className="block text-sm font-medium">Screenshot (optional)</span><div className="beam-actions"><Button type="button" variant="ghost" disabled={busy || reading} onClick={() => fileInput.current?.click()}><Icon name="file-text" size={14} />{fileName ? "Choose another screenshot" : "Attach screenshot"}</Button>{fileName && <span className="beam-attachment-name">{reading ? `Preparing ${fileName}…` : fileName}</span>}{(screenshot || reading) && <Button type="button" variant="ghost" disabled={busy} onClick={clearAttachment}>Remove screenshot</Button>}</div><input ref={fileInput} className="sr-only" type="file" aria-label="Screenshot (optional)" accept="image/png,image/jpeg" disabled={busy} onChange={event => void attachment(event.target.files?.[0])} /><p className="text-xs text-ink-secondary">PNG or JPEG, up to 10 MB. Large screenshots are resized for review. Check that your screenshot does not include secrets or personal information.</p></div>
    <p className="text-xs text-ink-secondary">The publisher and the share's other reviewers see your name, email, decision, comment and screenshot.</p>
    <div className="beam-actions"><Button type="submit" disabled={busy || reading || !sendable} aria-describedby={!sendable ? `beam-send-hint-${share.id}` : undefined}>{busy ? "Sending…" : "Send feedback"}</Button>{!sendable && !busy && <span id={`beam-send-hint-${share.id}`} className="text-xs text-ink-secondary">Write feedback, attach a screenshot or choose Approve or Request changes to send.</span>}</div>
  </form> : closed || mfa ? null : <p className="text-sm text-ink-secondary">{writeUncertain ? "Refresh feedback to check the last submission before trying again." : beamIsTerminal(share, clock.now()) ? "This share has ended, so no new feedback can be added." : "Feedback can be added while this share is available to your account."}</p>;
  const mfaPrompt = mfa && <BeamMfaPrompt verifying={verifying} onVerify={() => setVerifying(true)} onCancel={() => setVerifying(false)}
    action={mfa === "send" ? "Send review feedback" : "Open review feedback"}
    reason={mfa === "send" ? "Your organization requires a recent MFA check to send review feedback. Your draft is kept." : "Your organization requires a recent MFA check to read and send review feedback."}
    onVerified={async () => { const sending = mfa === "send"; setVerifying(false); if (sending) { setMfa(""); await send(); } else setReload(n => n + 1); }} />;
  return <section id="beam-review-feedback" tabIndex={-1} className="beam-feedback beam-section space-y-4" aria-label="Review feedback"><div className="beam-section-heading"><h2 className="font-semibold">Review feedback</h2>{!closed && <RefreshButton label="Refresh feedback" disabled={busy} onClick={() => setReload(n => n + 1)} />}</div><ErrorText>{error}</ErrorText>{notice && <p role="status">{notice}</p>}
    {uncertain ? <p role="status">Refresh the share to check current feedback access.</p> : closed ? <p role="status" className="text-sm text-ink-secondary">{closed}</p> : <>
      {mfa === "read" && mfaPrompt}{form}{mfa === "send" && mfaPrompt}
      {!data ? !error && !mfa && <Loading label="Loading review feedback…" /> : !data.items.length ? page === 0 && <p className="beam-feedback-empty text-sm text-ink-secondary">{publisher ? "No feedback yet. Reviewers' comments appear here." : "No feedback yet. Yours will be the first."}</p> : <><h3 className="beam-feedback-history">Earlier feedback</h3><ul className="beam-comment-list" aria-label="Review comments">{data.items.map(item => { const image = beamScreenshotURL(orgId, share.id, item); const author = personLabel({ name: item.author_name, email: item.author_email }, "Participant"); return <li key={item.id} className="space-y-2"><div className="flex flex-wrap justify-between gap-2"><span className="font-medium text-sm">{author}</span><span className="beam-status">{decisionLabel[item.status] ?? "Comment"}</span></div>{item.body && <p className="whitespace-pre-wrap text-sm">{item.body}</p>}{image && <a href={image} target="_blank" rel="noopener noreferrer" className="text-brand text-sm">View screenshot from {author}</a>}<p className="text-xs text-ink-secondary">{new Date(item.created_at).toLocaleString()}</p></li>; })}</ul></>}
      {data && (data.items.length > 0 || page > 0) && <Pagination page={page} count={data.items.length} limit={pageSize} label="comments" onChange={setPage} onPageSizeChange={size => { setPageSize(size); setPage(0); }} />}
    </>}
  </section>;
}
export function BeamNotifications({ orgId }: { orgId: string }) {
  const [open, setOpen] = useState(false); const [data, setData] = useState<BeamPage<BeamNotification> | null>(null); const [error, setError] = useState(""); const [page, setPage] = useState(0); const [pageSize, setPageSize] = useState(20); const [reload, setReload] = useState(0);
  const [mfa, setMfa] = useState(false); const [verifying, setVerifying] = useState(false);
  useEffect(() => { if (!open) return; let current = true; setData(null); setError(""); void beamRoomsApi.notifications(orgId, page * pageSize, pageSize).then(result => { if (!current) return; if (result.ok) { setMfa(false); setData(result.data); } else if (beamNeedsMfa(result.code)) setMfa(true); else setError(result.error); }); return () => { current = false; }; }, [orgId, open, page, pageSize, reload]);
  useEffect(() => { if (!open) return; const poll = window.setInterval(() => setReload(n => n + 1), 30000); const focus = () => setReload(n => n + 1); window.addEventListener("focus", focus); return () => { window.clearInterval(poll); window.removeEventListener("focus", focus); }; }, [open]);
  return <section aria-label="Sharing updates" className="beam-updates"><Button variant="ghost" aria-expanded={open} title="Ready to open, expiring soon and new feedback" onClick={() => setOpen(value => !value)}><Icon name="bell" size={15} />{open ? "Hide sharing updates" : "Sharing updates"}</Button>{open && <Modal placement="right" size="wide" title="Sharing updates" showClose onDismiss={() => setOpen(false)}><div className="space-y-4"><RefreshButton label="Refresh updates" onClick={() => setReload(n => n + 1)} /><p className="text-sm text-ink-secondary">Apps shared with you that are ready to open, shares about to expire, and new review feedback, on your shares and on apps shared with you.</p>{error ? <><ErrorText>{error}</ErrorText><Button onClick={() => setReload(n => n + 1)}>Retry sharing updates</Button></> : mfa ? <BeamMfaPrompt verifying={verifying} onVerify={() => setVerifying(true)} onCancel={() => setVerifying(false)} action="Show sharing updates" reason="Your organization requires a recent MFA check to show sharing updates." onVerified={() => { setVerifying(false); setReload(n => n + 1); }} /> : !data ? <Loading label="Loading sharing updates…" /> : !data.items.length ? <AppAccessEmptyState title="No sharing updates right now." description="You'll see apps ready to open, shares about to expire and new feedback here." /> : <ul className="space-y-3">{data.items.map(item => <li key={item.id}><Link to={`/beam/shares/${encodeURIComponent(item.share_id)}`} className="text-brand text-sm">{item.title}</Link><p className="text-xs text-ink-secondary">{new Date(item.created_at).toLocaleString()}</p></li>)}</ul>}{data && <Pagination page={page} count={data.items.length} limit={pageSize} label="updates" onChange={setPage} onPageSizeChange={size => { setPageSize(size); setPage(0); }} />}</div></Modal>}</section>;
}
