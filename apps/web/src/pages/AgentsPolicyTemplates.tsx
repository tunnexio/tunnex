import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AgentsTabRail } from "../components/AgentsTabRail";
import { Button, Card, DataTable, EmptyState, ErrorText, Field, Input, Loading, Modal, PageHeader, Select } from "../components/ui";
import { api, apiErrorMessage, loadOne, type AgentGroup, type AgentPolicyTemplate, type AgentPolicyTemplateAssignment, type AgentPolicyTemplatePreview, type AgentPolicyTemplateVersion, type Resource } from "../lib/api";
import { relativeAge } from "../lib/format";
import { AgentsManagementGate } from "./AgentsManagementGate";

export default function AgentsPolicyTemplates() {
  return <div className="space-y-5">
    <PageHeader title="Policy templates" subtitle="Build reusable, versioned access intent for agent groups." />
    <AgentsTabRail />
    <AgentsManagementGate>{(orgId) => <PolicyTemplatesWorkspace key={orgId} orgId={orgId} />}</AgentsManagementGate>
  </div>;
}

function PolicyTemplatesWorkspace({ orgId }: { orgId: string }) {
  const [search, setSearch] = useSearchParams();
  const templateId = search.get("template") ?? "";
  const groupId = search.get("group") ?? "";
  const query = search.get("q") ?? "";
  const [templates, setTemplates] = useState<AgentPolicyTemplate[] | null>(null);
  const [groups, setGroups] = useState<AgentGroup[] | null>(null);
  const [resources, setResources] = useState<Resource[] | null>(null);
  const [assignments, setAssignments] = useState<AgentPolicyTemplateAssignment[] | null>(null);
  const [versions, setVersions] = useState<AgentPolicyTemplateVersion[] | null>(null);
  const [name, setName] = useState("");
  const [resourceId, setResourceId] = useState("");
  const [versionId, setVersionId] = useState("");
  const [preview, setPreview] = useState<AgentPolicyTemplatePreview | null>(null);
  const [dialog, setDialog] = useState<"create" | "rename" | "version" | "archive" | "apply" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const selected = templates?.find((template) => template.id === templateId);
  const selectedGroup = groups?.find((group) => group.id === groupId);
  const selectedAssignments = (assignments ?? []).filter((assignment) => assignment.template_id === templateId);
  const visibleTemplates = (templates ?? []).filter((template) => template.name.toLowerCase().includes(query.trim().toLowerCase()));

  const reload = useCallback(async () => {
    setError("");
    const [templateResult, groupResult, resourceResult, assignmentResult] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-policy-templates", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-groups", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/resources", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-policy-template-assignments", { params: { path: { orgId } } })),
    ]);
    if (!templateResult.ok || !groupResult.ok || !resourceResult.ok || !assignmentResult.ok) {
      setError("Could not load policy templates. Refresh to retry.");
      return;
    }
    setTemplates(templateResult.data);
    setGroups(groupResult.data);
    setResources(resourceResult.data);
    setAssignments(assignmentResult.data);
  }, [orgId]);

  useEffect(() => { void reload(); }, [reload]);
  useEffect(() => {
    let cancelled = false;
    setVersions(null);
    setPreview(null);
    if (!templateId) return;
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-policy-templates/{templateId}/versions", { params: { path: { orgId, templateId } } })).then((result) => {
      if (cancelled) return;
      if (!result.ok) { setError(result.error); return; }
      setVersions(result.data);
      setVersionId((id) => result.data.some((version) => version.id === id) ? id : (result.data[0]?.id ?? ""));
    });
    return () => { cancelled = true; };
  }, [orgId, templateId]);

  const choose = (key: "template" | "group" | "q", value: string | null) => {
    const next = new URLSearchParams(search);
    value ? next.set(key, value) : next.delete(key);
    setSearch(next);
  };
  async function action(call: () => Promise<{ error?: unknown }>, fallback: string, success: string) {
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await call();
      if (result.error) { setError(apiErrorMessage(result.error, fallback)); return false; }
      setNotice(success); return true;
    } catch { setError("Could not reach the API."); return false; } finally { setBusy(false); }
  }
  async function create() {
    if (!name.trim()) return;
    if (await action(() => api.POST("/api/v1/organizations/{orgId}/agent-policy-templates", { params: { path: { orgId } }, body: { name: name.trim() } }), "Could not create the template.", "Policy template created. Add an immutable version before assigning it.")) {
      setDialog(null); setName(""); await reload();
    }
  }
  async function rename() {
    if (!templateId || !name.trim()) return;
    if (await action(() => api.PATCH("/api/v1/organizations/{orgId}/agent-policy-templates/{templateId}", { params: { path: { orgId, templateId } }, body: { name: name.trim() } }), "Could not rename the template.", "Policy template renamed.")) { setDialog(null); await reload(); }
  }
  async function archive() {
    if (!templateId) return;
    if (await action(() => api.DELETE("/api/v1/organizations/{orgId}/agent-policy-templates/{templateId}", { params: { path: { orgId, templateId } } }), "Could not archive the template.", "Template archived. Existing assignments remain until you remove them.")) { setDialog(null); choose("template", null); await reload(); }
  }
  async function createVersion() {
    if (!templateId || !resourceId) return;
    if (!await action(() => api.POST("/api/v1/organizations/{orgId}/agent-policy-templates/{templateId}/versions", { params: { path: { orgId, templateId } }, body: { items: [{ destination_kind: "resource", destination_id: resourceId }] } }), "Could not create the immutable version.", "Immutable version created. Preview its impact before assigning it.")) return;
    setDialog(null);
    const refreshed = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-policy-templates/{templateId}/versions", { params: { path: { orgId, templateId } } }));
    if (refreshed.ok) { setVersions(refreshed.data); setVersionId(refreshed.data[0]?.id ?? ""); } else setError(refreshed.error);
  }
  async function previewApply() {
    if (!groupId || !versionId) return;
    setBusy(true); setError("");
    const result = await api.POST("/api/v1/organizations/{orgId}/agent-policy-template-preview", { params: { path: { orgId } }, body: { group_id: groupId, template_version_id: versionId } });
    setBusy(false);
    if (result.error || !result.data) { setError(apiErrorMessage(result.error, "Could not preview the policy change.")); return; }
    setPreview(result.data); setDialog("apply");
  }
  async function apply() {
    if (!groupId || !versionId || !preview) return;
    if (await action(() => api.POST("/api/v1/organizations/{orgId}/agent-policy-template-assignments", { params: { path: { orgId } }, body: { group_id: groupId, template_version_id: versionId, preview_digest: preview.digest, idempotency_key: crypto.randomUUID() } }), "Could not apply the template.", `Template queued for ${preview.affected_agents} affected agents; ${preview.changed_gateways} gateway artifacts changed.`)) { setDialog(null); setPreview(null); await reload(); }
  }
  async function removeAssignment(assignment: AgentPolicyTemplateAssignment) {
    if (await action(() => api.DELETE("/api/v1/organizations/{orgId}/agent-policy-template-assignments/{assignmentId}", { params: { path: { orgId, assignmentId: assignment.id } } }), "Could not remove the assignment.", `Assignment removed. ${assignment.rule_count} assignment-owned rules may be withdrawn; shared rules remain.`)) await reload();
  }

  if (!templates || !groups || !resources || !assignments) return <Card><Loading label="Loading policy templates…" /></Card>;
  const createButton = <Button onClick={() => { setName(""); setDialog("create"); }}>Create template</Button>;
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <span className="text-sm text-ink-tertiary">{templates.length} {templates.length === 1 ? "template" : "templates"}</span>{templates.length > 0 && createButton}
    </div>
    <ErrorText>{error}</ErrorText>{notice && <p role="status" className="text-sm text-ok">{notice}</p>}
    {templates.length === 0 ? <Card className="max-w-2xl"><EmptyState action={createButton}><strong className="block text-sm text-ink-heading">Create reusable policy intent</strong><span className="mt-1 block">Policy templates let you preview a version’s impact before applying it to an Agent Group. Create a template, then add its immutable versions.</span><Link className="mt-3 inline-flex min-h-10 items-center text-sm font-medium text-accent-400 hover:underline" to="/access/groups?type=agents">Manage agent groups</Link></EmptyState></Card> : <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(23rem,.9fr)]">
      <Card><div className="border-b border-white/10 p-3"><Input aria-label="Search policy templates" value={query} onChange={(event) => choose("q", event.target.value || null)} placeholder="Search policy templates" /></div><DataTable caption="Agent policy templates" rows={visibleTemplates} rowKey={(template) => template.id} failed={false} filterable={false} pageSize={0} empty={<>No templates match this search.</>} columns={[
        { key: "name", header: "Template", cell: (template) => <button type="button" onClick={() => choose("template", template.id)} className="font-medium text-ink-heading hover:underline">{template.name}</button> },
        { key: "version", header: "Latest version", cell: (template) => template.id === templateId && versions ? (versions[0] ? `v${versions[0].version}` : "None") : "Select to load" },
        { key: "assigned", header: "Assignments", cell: (template) => assignments.filter((item) => item.template_id === template.id).length },
        { key: "status", header: "Lifecycle", cell: () => "Active" },
      ]} /></Card>
      <Card>{!selected ? <EmptyState>Select a template to inspect versions, impact previews, and assignments.</EmptyState> : <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-2"><div className="min-w-0"><h2 className="text-sm font-semibold text-ink-heading">{selected.name}</h2><p className="mt-1 text-cell text-ink-tertiary">Template-managed rules remain authoritative in Access Policies, where they link back here.</p></div><div className="flex flex-wrap gap-2"><Button size="sm" variant="ghost" onClick={() => { setName(selected.name); setDialog("rename"); }}>Rename</Button><Button size="sm" variant="danger" onClick={() => setDialog("archive")}>Archive</Button></div></div>
        <div><div className="flex flex-wrap items-center justify-between gap-2"><h3 className="text-sm font-medium text-ink-heading">Immutable versions</h3><Button size="sm" onClick={() => setDialog("version")}>New version</Button></div>{versions === null ? <Loading label="Loading versions…" /> : <Select aria-label="Template version" value={versionId} onChange={(event) => setVersionId(event.target.value)} className="mt-2">{versions.length === 0 ? <option value="">No versions</option> : versions.map((version) => <option key={version.id} value={version.id}>v{version.version}</option>)}</Select>}</div>
        <div className="border-t border-white/10 pt-3"><h3 className="text-sm font-medium text-ink-heading">Assign after preview</h3><p className="mt-1 text-cell text-ink-tertiary">Select an existing Agent Group. Group membership has one management home.</p><Link className="mt-2 inline-flex min-h-10 items-center text-sm font-medium text-accent-400 hover:underline" to="/access/groups?type=agents">Manage agent groups</Link><Select aria-label="Assignment group" className="mt-2" value={groupId} onChange={(event) => choose("group", event.target.value || null)}><option value="">Select group</option>{groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</Select><Button className="mt-2" size="sm" disabled={busy || !groupId || !versionId} onClick={() => void previewApply()}>Preview impact</Button></div>
        <div className="border-t border-white/10 pt-3"><h3 className="text-sm font-medium text-ink-heading">Current assignments</h3>{selectedAssignments.length === 0 ? <p className="mt-2 text-cell text-ink-tertiary">No active assignments.</p> : <div className="mt-2 space-y-2">{selectedAssignments.map((assignment) => <div className="flex flex-wrap items-center justify-between gap-2 text-cell" key={assignment.id}><span>{assignment.group_name} · v{assignment.version} · {relativeAge(assignment.applied_at)}</span><Button size="sm" variant="danger" disabled={busy} onClick={() => void removeAssignment(assignment)}>Remove</Button></div>)}</div>}</div>
      </div>}</Card>
    </div>}
    {dialog === "create" && <Modal title="Create policy template" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !name.trim()} onClick={() => void create()}>Create template</Button></>}><p className="mb-3 text-cell text-ink-tertiary">Name reusable access intent. Next, add an immutable version and preview it before any group receives it.</p><Field label="Template name"><Input autoFocus value={name} onChange={(event) => setName(event.target.value)} /></Field></Modal>}
    {dialog === "rename" && <Modal title="Rename policy template" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !name.trim()} onClick={() => void rename()}>Save name</Button></>}><Field label="Template name"><Input autoFocus value={name} onChange={(event) => setName(event.target.value)} /></Field></Modal>}
    {dialog === "version" && <Modal title="Create immutable version" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy || !resourceId} onClick={() => void createVersion()}>Create version</Button></>}><p className="mb-3 text-cell text-ink-tertiary">This creates a new immutable version; it does not change an existing assignment.</p><Field label="Destination resource"><Select value={resourceId} onChange={(event) => setResourceId(event.target.value)}><option value="">Select resource</option>{resources.map((resource) => <option key={resource.id} value={resource.id}>{resource.name}</option>)}</Select></Field></Modal>}
    {dialog === "apply" && preview && <Modal title="Confirm template assignment" onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button disabled={busy} onClick={() => void apply()}>Apply template</Button></>}><p className="text-cell text-ink-tertiary">Apply v{versions?.find((version) => version.id === versionId)?.version ?? "?"} to {selectedGroup?.name ?? "the selected group"}: {preview.affected_agents} agents, {preview.created_rules} new rules, and {preview.changed_gateways} gateways will change. You can remove this assignment later; shared rules remain.</p></Modal>}
    {dialog === "archive" && <Modal title="Archive policy template" danger onDismiss={() => setDialog(null)} actions={<><Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void archive()}>Archive template</Button></>}><p className="text-cell text-ink-tertiary">This archives the reusable template. {selectedAssignments.length} existing assignments remain until removed separately; this action does not silently withdraw access.</p></Modal>}
  </div>;
}
