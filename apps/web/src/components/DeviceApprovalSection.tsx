import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorMessage, loadOne, type Device, type DeviceApproval } from "../lib/api";
import { relativeAge } from "../lib/format";
import { NO_ADDRESS } from "../lib/postureview";
import { Button, Card, DataTable, ErrorText, Modal } from "./ui";
import { LoadRetry } from "./LoadRetry";

export function DeviceApprovalSection({
  orgId,
  canManage,
}: {
  orgId: string;
  canManage: boolean;
}) {
  const [mode, setMode] = useState<"off" | "on" | null>(null);
  const [modeError, setModeError] = useState<string | null>(null);
  const [pending, setPending] = useState<Device[]>([]);
  const [pendingError, setPendingError] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState<{ action: "approve" | "reject"; devices: Device[] } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const [dr, pr] = await Promise.all([
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/device-approval", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/devices/pending", {
          params: { path: { orgId } },
        }),
      ),
    ]);
    setModeError(dr.ok ? null : dr.error);
    if (dr.ok) setMode((dr.data as DeviceApproval).mode);
    // [3]: a failed pending fetch must NOT render "No devices awaiting approval" — that hides
    // a device blocked from connecting. Show retry.
    setPendingError(pr.ok ? null : pr.error);
    if (pr.ok) setPending(pr.data as Device[]);
  }, [orgId]);
  useEffect(() => {
    load();
  }, [load]);

  async function decide() {
    if (!confirmation) return;
    const { action, devices } = confirmation;
    setBusy(true); setErr(null); setNotice(null);
    const results = await Promise.all(devices.map(async (device) => {
      const path = action === "approve"
        ? "/api/v1/organizations/{orgId}/devices/{deviceId}/approve"
        : "/api/v1/organizations/{orgId}/devices/{deviceId}/reject";
      const { error } = await api.POST(path, { params: { path: { orgId, deviceId: device.id } } });
      return { device, error };
    }));
    setBusy(false);
    const failed = results.filter((result) => result.error);
    const succeeded = results.length - failed.length;
    if (failed.length) setErr(`${succeeded} of ${results.length} devices ${action === "approve" ? "approved" : "rejected"}. ${failed.map((result) => `${result.device.name}: ${apiErrorMessage(result.error, `Could not ${action} the device.`)}`).join(" ")}`);
    else setNotice(`${succeeded} device${succeeded === 1 ? "" : "s"} ${action === "approve" ? "approved" : "rejected"}.`);
    setConfirmation(null);
    await load();
  }

  return (
    <Card className="mt-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-300">
            Device approval
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            {mode === "on"
              ? "On. new devices enroll pending and cannot connect until approved."
              : mode === "off"
                ? "Off. new devices are active on enrollment."
                : modeError
                  ? "n/a"
                  : "…"}
          </p>
        </div>
        <Link className="inline-flex min-h-10 items-center text-sm font-medium text-accent-400 hover:underline" to="/settings?section=access-security">
          Manage in Org Settings
        </Link>
      </div>
      {modeError && <LoadRetry error={modeError} onRetry={load} />}
      <ErrorText>{err}</ErrorText>
      {notice && <p role="status" className="mt-2 text-sm text-ok">{notice}</p>}

      {/* ⛔ PENDING DEVICES AS A TABLE. A device awaiting approval is the ONE list here where the operator
          is being asked to make a security decision — and the row gave them a name and an IP with no owner,
          no platform, no age. Approving a device you cannot attribute is approving a device.

          ⚠ The wait is shown because it is the fact that decides urgency: a request from four minutes ago
          and one from nine days ago are different situations wearing the same row. */}
      {pendingError ? (
        <LoadRetry error={pendingError} onRetry={load} />
      ) : (
        <DataTable<Device>
          caption="Pending devices"
          rows={pending}
          rowKey={(d) => d.id}
          failed={false}
          pageSize={10}
          empty="No devices awaiting approval."
          rowActions={
            canManage
              ? [
                  {
                    key: "approve",
                    label: "Approve",
                    run: (ds: Device[]) => setConfirmation({ action: "approve", devices: ds }),
                  },
                  {
                    key: "reject",
                    label: "Reject",
                    danger: true,
                    run: (ds: Device[]) => setConfirmation({ action: "reject", devices: ds }),
                  },
                ]
              : undefined
          }
          columns={[
            {
              key: "name",
              header: "Device",
              sortValue: (d) => d.name,
              cell: (d) => <span className="text-slate-200">{d.name}</span>,
            },
            {
              key: "ip",
              header: "Address",
              sortValue: (d) => d.assigned_ip ?? "",
              cell: (d) => (
                <span className="font-mono text-xs text-slate-500">
                  {d.assigned_ip ?? NO_ADDRESS}
                </span>
              ),
            },
            {
              key: "owner",
              header: "Owner",
              sortValue: (d) => d.owner_email ?? "",
              cell: (d) => d.owner_email ? (
                <span className="text-xs text-slate-300">{d.owner_email}</span>
              ) : (
                <span className="text-xs text-slate-500">Owner unavailable</span>
              ),
            },
            {
              key: "waiting",
              header: "Waiting",
              sortValue: (d) => Date.parse(d.created_at),
              cell: (d) => (
                <span className="text-xs text-slate-500">
                  {relativeAge(d.created_at)}
                </span>
              ),
            },
          ]}
        />
      )}
      {confirmation && <Modal title={`${confirmation.action === "approve" ? "Approve" : "Reject"} pending device${confirmation.devices.length === 1 ? "" : "s"}?`} danger={confirmation.action === "reject"} onDismiss={() => !busy && setConfirmation(null)} actions={<><Button variant="ghost" disabled={busy} onClick={() => setConfirmation(null)}>Cancel</Button><Button variant={confirmation.action === "reject" ? "danger" : "primary"} disabled={busy} onClick={() => void decide()}>{busy ? "Applying…" : confirmation.action === "approve" ? "Approve device" : "Reject device"}</Button></>}><p className="text-cell text-ink-tertiary">{confirmation.action === "approve" ? "Approval allows these pending devices to connect under the organization’s current policy. Recovery is revocation through Devices." : "Rejection keeps these devices from connecting. Recovery requires a fresh new enrollment request."}</p><ul className="mt-3 max-h-40 space-y-1 overflow-auto text-cell text-ink-heading">{confirmation.devices.map((device) => <li key={device.id}>{device.name}{device.assigned_ip ? ` / ${device.assigned_ip}` : " / no assigned address"}{device.owner_email ? ` / ${device.owner_email}` : " / owner unavailable"}</li>)}</ul><p className="mt-3 text-xs text-ink-tertiary">The server is authoritative. If a bulk action partially fails, successful decisions remain applied and each failed device is reported after refresh.</p></Modal>}
    </Card>
  );
}
