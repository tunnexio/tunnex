import type { components } from "@tunnex/shared";

type Record = components["schemas"]["AgentWorkflowProvenanceRecord"];

export function AgentWorkflowProvenancePanel({ records }: { records: Record[] }) {
  if (records.length === 0) return null;
  return <div data-testid="agent-workflow-provenance" className="rounded-md border border-slate-700 p-3 text-xs text-slate-300"><div className="font-semibold text-ink-heading">Workflow provenance</div><p className="mt-1 text-slate-500">Signed evidence only. This view never invokes a tool or grants MCP access.</p>{records.map((record) => record.verification_state === "verified" && record.verified_chain ? <div key={record.id} className="mt-2 border-t border-slate-800 pt-2"><div className="font-medium text-success">Verified</div><div>Agent → {record.verified_chain.workflow_id} / {record.verified_chain.run_id} → {record.verified_chain.tool} → {record.verified_chain.resource}</div><div className="text-slate-500">Trigger {record.verified_chain.trigger_kind} · initiator {record.verified_chain.initiating_subject_ref} · received {record.received_at}</div></div> : <div key={record.id} className="mt-2 border-t border-slate-800 pt-2"><div className="font-medium text-warning">Unverified context</div><div className="text-slate-500">{record.verification_reason} · received {record.received_at}. Workflow, tool, resource, and initiator are intentionally hidden.</div></div>)}</div>;
}
