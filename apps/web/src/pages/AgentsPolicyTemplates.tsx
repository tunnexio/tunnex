import { HelpTooltip } from "../components/HelpTooltip";
import "../network-workspaces.css";
import "../agents-workspace.css";
import "../agents-management-workspace.css";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AgentsTabRail } from "../components/AgentsTabRail";
import { LoadRetry } from "../components/LoadRetry";
import { Button, DataTable, ErrorText, Field, Input, Loading, Modal, PageHeader, Select, RefreshButton } from "../components/ui";
import { api, apiErrorMessage, loadOne, type AgentGroup, type AgentPolicyTemplate, type AgentPolicyTemplateAssignment, type AgentPolicyTemplatePreview, type AgentPolicyTemplateVersion, type Resource } from "../lib/api";
import { relativeAge } from "../lib/format";
import { useOrg } from "../lib/useOrg";
import { AgentsManagementGate } from "./AgentsManagementGate";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import AppAccessPagination from "../components/AppAccessPagination";
import AppAccessEmptyState from "../components/AppAccessEmptyState";

export default function AgentsPolicyTemplates() {
  const { org } = useOrg();
  const enabled = Boolean(org?.agent_policy_templates_enabled);
  return <div className="network-management agents-workspace agents-management space-y-5">
    <PageHeader navigationTitle title="Policy templates" subtitle={org?.name} />
    <AgentsTabRail />
    <AgentsManagementGate>{(orgId) => enabled ? <PolicyTemplatesWorkspace key={orgId} orgId={orgId} /> : <AppAccessEmptyState icon={null} title="Agent groups and policy templates are turned off" description="Enable this organization’s opt-in to configure reusable network policies." action={<Link className="agents-management-link" to="/settings?section=features&feature=agent-templates">Configure AI Agent settings</Link>} />}</AgentsManagementGate>
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
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const [assignmentPage, setAssignmentPage] = useState(1), [assignmentSize, setAssignmentSize] = useState(20);
  const [removing, setRemoving] = useState<AgentPolicyTemplateAssignment | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [versionAttempt, setVersionAttempt] = useState(0);
  const [versionError, setVersionError] = useState("");
  const [previewTarget, setPreviewTarget] = useState<{ template: string; group: string; version: string; idempotency: string } | null>(null);
  const alive = useRef(true), generation = useRef(0), locked = useRef(false);
  const target = useRef({ templateId, groupId, versionId }); target.current = { templateId, groupId, versionId };
  useEffect(() => { alive.current = true; return () => { alive.current = false; generation.current++; }; }, []);
  const selected = templates?.find((template) => template.id === templateId);
  const selectedGroup = groups?.find((group) => group.id === groupId);
  const selectedAssignments = (assignments ?? []).filter((assignment) => assignment.template_id === templateId);
  const visibleTemplates = (templates ?? []).filter((template) => template.name.toLowerCase().includes(query.trim().toLowerCase()));

  const reload = useCallback(async () => {
    const request = ++generation.current;
    setError("");
    setLoadFailed(true);
    const [templateResult, groupResult, resourceResult, assignmentResult] = await Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-policy-templates", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-groups", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/resources", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-policy-template-assignments", { params: { path: { orgId } } })),
    ]);
    if (!alive.current || request !== generation.current) return;
    if (!templateResult.ok || !groupResult.ok || !resourceResult.ok || !assignmentResult.ok) {
      setLoadFailed(true);
      setError("Could not load policy templates. Refresh to retry.");
      return;
    }
    setLoadFailed(false);
    setTemplates(templateResult.data);
    setGroups(groupResult.data);
    setResources(resourceResult.data);
    setAssignments(assignmentResult.data);
  }, [orgId]);

  useEffect(() => { void reload(); }, [reload]);
  useEffect(() => { setDialog(null); setRemoving(null); }, [templateId]);
  useEffect(() => {
    let cancelled = false;
    setVersions(null); setVersionError("");
    setPreview(null); setPreviewTarget(null); setVersionId(""); setAssignmentPage(1);
    if (!templateId) return;
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-policy-templates/{templateId}/versions", { params: { path: { orgId, templateId } } })).then((result) => {
      if (cancelled) return;
      if (!result.ok) { setVersionError(result.error); return; }
      setVersions(result.data);
      setVersionId((id) => result.data.some((version) => version.id === id) ? id : (result.data[0]?.id ?? ""));
    });
    return () => { cancelled = true; };
  }, [orgId, templateId, versionAttempt]);

  const choose = (key: "template" | "group" | "q", value: string | null) => {
    if (busy) return;
    if (key !== "q") { setPreview(null); setPreviewTarget(null); } else setPage(1);
    const next = new URLSearchParams(search);
    value ? next.set(key, value) : next.delete(key);
    setSearch(next);
  };
  async function action(call: () => Promise<{ error?: unknown }>, fallback: string, success: string) {
    if (locked.current || loadFailed || !alive.current) return false;
    locked.current = true; setBusy(true); setError(""); setNotice("");
    try {
      const result = await call();
      if (!alive.current) return false;
      if (result.error) { setError(apiErrorMessage(result.error, fallback)); return false; }
      setNotice(success); return true;
    } catch { if (alive.current) setError("Could not reach the API. Refresh the saved state before retrying."); return false; } finally { locked.current = false; if (alive.current) setBusy(false); }
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
    const requestedTemplate = templateId;
    if (!await action(() => api.POST("/api/v1/organizations/{orgId}/agent-policy-templates/{templateId}/versions", { params: { path: { orgId, templateId } }, body: { items: [{ destination_kind: "resource", destination_id: resourceId }] } }), "Could not create the immutable version.", "Immutable version created. Preview its impact before assigning it.")) return;
    setDialog(null);
    const refreshed = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/agent-policy-templates/{templateId}/versions", { params: { path: { orgId, templateId } } }));
    if (!alive.current || target.current.templateId !== requestedTemplate) return;
    if (refreshed.ok) { setVersions(refreshed.data); setVersionId(refreshed.data[0]?.id ?? ""); } else setError(refreshed.error);
  }
  async function previewApply() {
    if (locked.current || loadFailed || !groupId || !versionId || !versions?.some((v) => v.id === versionId)) return;
    const requested = { templateId, groupId, versionId };
    locked.current = true; setBusy(true); setError("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/agent-policy-template-preview", { params: { path: { orgId } }, body: { group_id: groupId, template_version_id: versionId } });
      if (!alive.current || Object.keys(requested).some((key) => requested[key as keyof typeof requested] !== target.current[key as keyof typeof requested])) return;
      if (result.error || !result.data) { setError(apiErrorMessage(result.error, "Could not preview the policy change.")); return; }
      setPreview(result.data); setPreviewTarget({ template: templateId, group: groupId, version: versionId, idempotency: crypto.randomUUID() }); setDialog("apply");
    } catch { if (alive.current) setError("Could not preview the policy change. Refresh before retrying."); }
    finally { locked.current = false; if (alive.current) setBusy(false); }
  }
  async function apply() {
    if (!preview || !previewTarget || previewTarget.template !== templateId || previewTarget.group !== groupId || previewTarget.version !== versionId) return;
    if (await action(() => api.POST("/api/v1/organizations/{orgId}/agent-policy-template-assignments", { params: { path: { orgId } }, body: { group_id: previewTarget.group, template_version_id: previewTarget.version, preview_digest: preview.digest, idempotency_key: previewTarget.idempotency } }), "Could not apply the template.", `Template queued for ${preview.affected_agents} affected agents; ${preview.changed_gateways} gateway artifacts changed.`)) { setDialog(null); setPreview(null); setPreviewTarget(null); await reload(); }
  }
  async function removeAssignment(assignment: AgentPolicyTemplateAssignment) {
    const removed = await action(() => api.DELETE("/api/v1/organizations/{orgId}/agent-policy-template-assignments/{assignmentId}", { params: { path: { orgId, assignmentId: assignment.id } } }), "Could not remove the assignment.", `Assignment removed. ${assignment.rule_count} assignment-owned rules may be withdrawn; shared rules remain.`);
    if (removed) await reload();
    return removed;
  }

  if (!templates || !groups || !resources || !assignments) return error ? <LoadRetry error={error} onRetry={() => void reload()} /> : <Loading label="Loading policy templates…" />;
  const currentPage = Math.min(page, Math.max(1, Math.ceil(visibleTemplates.length / pageSize)));
  const tableRows = visibleTemplates.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const currentAssignments = Math.min(assignmentPage, Math.max(1, Math.ceil(selectedAssignments.length / assignmentSize)));
  const assignmentRows = selectedAssignments.slice((currentAssignments - 1) * assignmentSize, currentAssignments * assignmentSize);
  const unavailable = busy || loadFailed;
  const refresh = () => { void reload(); setVersionAttempt((v) => v + 1); };
  const dismiss = () => { if (!busy) setDialog(null); };
  return <div className="agents-management-content">
    <ErrorText>{error}</ErrorText>{notice && <p role="status" className="agents-management-notice">{notice}</p>}
    {templateId ? selected ? <>
      <nav aria-label="Breadcrumb" className="agents-management-breadcrumb"><button disabled={busy} onClick={() => choose("template", null)}>Policy templates</button><span aria-hidden="true">/</span><span aria-current="page">{selected.name}</span></nav>
      <div className="agents-management-heading"><h2>{selected.name}</h2><div className="agents-management-actions"><RefreshButton label="Refresh templates" disabled={busy} onClick={refresh} /><AppAccessRowMenu label={`Actions for ${selected.name}`} actions={[
        { key: "rename", label: "Rename", disabledReason: unavailable ? "Refresh the saved state or finish the current action first." : undefined, onSelect: () => { setName(selected.name); setDialog("rename"); } },
        { key: "archive", label: "Archive", danger: true, disabledReason: unavailable ? "Refresh the saved state or finish the current action first." : undefined, onSelect: () => setDialog("archive") },
      ]} /></div></div>
      <div className="agents-management-toolbar"><h3>Version & assignment</h3><Button variant="ghost" disabled={unavailable} onClick={() => setDialog("version")}>New version</Button></div>
      <div className="agents-management-assignment-fields">
        {versions === null ? versionError ? <LoadRetry error={versionError} onRetry={() => setVersionAttempt((attempt) => attempt + 1)} /> : <Loading label="Loading versions…" /> : <Field label="Template version"><Select disabled={unavailable} value={versionId} onChange={(event) => { setVersionId(event.target.value); setPreview(null); setPreviewTarget(null); }}>{versions.length === 0 ? <option value="">No versions</option> : versions.map((version) => <option key={version.id} value={version.id}>v{version.version}</option>)}</Select></Field>}
        <Field label="Assignment group"><Select disabled={unavailable} value={groupId} onChange={(event) => choose("group", event.target.value || null)}><option value="">Select group</option>{groups.map((group) => <option key={group.id} value={group.id}>{group.name}</option>)}</Select></Field>
        <Button disabled={unavailable || !groupId || !versions?.some((v) => v.id === versionId)} onClick={() => void previewApply()}>Preview impact</Button>
      </div>
      <div className="agents-management-toolbar"><h3>Current assignments</h3><Link className="agents-management-link" to="/agents/groups">Manage agent groups</Link></div>
      <DataTable variant="flat" caption="Template assignments" rows={assignmentRows} rowKey={(assignment) => assignment.id} failed={false} filterable={false} pageSize={0} empty={<p className="agents-management-inline-empty">No active assignments.</p>} columns={[
        { key: "group", header: "Agent group", cell: (assignment) => <span>{assignment.group_name} · v{assignment.version}</span> },
        { key: "rules", header: "Rules", cell: (assignment) => assignment.rule_count },
        { key: "applied", header: "Applied", cell: (assignment) => relativeAge(assignment.applied_at) },
        { key: "actions", header: "Actions", cell: (assignment) => <AppAccessRowMenu label={`Actions for assignment to ${assignment.group_name}`} actions={[{ key: "remove", label: "Remove", danger: true, disabledReason: unavailable ? "Refresh the saved state or finish the current action first." : undefined, onSelect: () => setRemoving(assignment) }]} /> },
      ]} />
      <AppAccessPagination maxOffset={null} page={currentAssignments} pageSize={assignmentSize} count={assignmentRows.length} hasNext={currentAssignments * assignmentSize < selectedAssignments.length} busy={busy} onPageChange={setAssignmentPage} onPageSizeChange={(size) => { setAssignmentSize(size); setAssignmentPage(1); }} />
      <details className="agents-management-help"><summary>How network templates apply</summary><p>Versions are immutable. Applying a version adds managed network rules; removing an assignment withdraws only its owned rules. Shared rules remain. Network restrictions require organization enforcement. Model grants and MCP tool permissions are configured separately.</p><Link className="agents-management-link" to="/access/policies">View Access Policies</Link></details>
    </> : <AppAccessEmptyState icon={null} title="Template unavailable" description="Refresh the inventory or return to policy templates." action={<Button variant="ghost" onClick={() => choose("template", null)}>Back to templates</Button>} /> : <>
      <div className="agents-management-toolbar"><Input aria-label="Search policy templates" value={query} onChange={(event) => choose("q", event.target.value || null)} placeholder="Search policy templates" /><div className="agents-management-actions"><HelpTooltip label="About policy templates">Reusable network rules for agent groups. Model grants and MCP tool permissions are configured separately; network restrictions require organization enforcement.</HelpTooltip><RefreshButton label="Refresh templates" disabled={busy} onClick={refresh} /><Button disabled={unavailable} onClick={() => { setName(""); setDialog("create"); }}>Create template</Button></div></div>
      <DataTable variant="flat" caption="Agent policy templates" rows={tableRows} rowKey={(template) => template.id} failed={false} filterable={false} pageSize={0} empty={<AppAccessEmptyState icon={null} title={query ? "No matching templates" : "No policy templates yet"} description={query ? "Try another template name." : "Create a template, add a version, then preview its network impact."} action={query ? <Button variant="ghost" onClick={() => choose("q", null)}>Clear search</Button> : undefined} />} columns={[
        { key: "name", header: "Template", cell: (template) => <button type="button" onClick={() => choose("template", template.id)} className="agents-management-name">{template.name}</button> },
        { key: "assigned", header: "Assignments", cell: (template) => assignments.filter((item) => item.template_id === template.id).length },
        { key: "actions", header: "Actions", cell: (template) => <AppAccessRowMenu label={`Actions for ${template.name}`} actions={[{ key: "open", label: "Versions & assignments", disabledReason: busy ? "Wait for the current action." : undefined, onSelect: () => choose("template", template.id) }]} /> },
      ]} />
      <AppAccessPagination maxOffset={null} page={currentPage} pageSize={pageSize} count={tableRows.length} hasNext={currentPage * pageSize < visibleTemplates.length} busy={busy} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />
    </>}
    {dialog === "create" && <Modal title="Create policy template" placement="right" size="enrollment" showClose onDismiss={dismiss} actions={<><Button variant="ghost" disabled={busy} onClick={dismiss}>Cancel</Button><Button disabled={unavailable || !name.trim()} onClick={() => void create()}>Create template</Button></>}><div className="agents-management-editor"><ErrorText>{error}</ErrorText><Field label="Template name"><Input autoFocus disabled={busy} maxLength={100} value={name} onChange={(event) => setName(event.target.value)} /></Field><p>Create a name first. Add an immutable version before assigning network access.</p></div></Modal>}
    {dialog === "rename" && <Modal title="Rename policy template" placement="right" size="enrollment" showClose onDismiss={dismiss} actions={<><Button variant="ghost" disabled={busy} onClick={dismiss}>Cancel</Button><Button disabled={unavailable || !name.trim()} onClick={() => void rename()}>Save name</Button></>}><div className="agents-management-editor"><ErrorText>{error}</ErrorText><Field label="Template name"><Input autoFocus disabled={busy} maxLength={100} value={name} onChange={(event) => setName(event.target.value)} /></Field></div></Modal>}
    {dialog === "version" && <Modal title="Create immutable version" placement="right" size="enrollment" showClose onDismiss={dismiss} actions={<><Button variant="ghost" disabled={busy} onClick={dismiss}>Cancel</Button><Button disabled={unavailable || !resourceId} onClick={() => void createVersion()}>Create version</Button></>}><div className="agents-management-editor"><ErrorText>{error}</ErrorText><p>Existing assignments keep their current version.</p>{resources.length === 0 && <p role="status">No destination resources yet. <Link className="agents-management-link" to="/access/resources">Create a resource</Link>, then return here.</p>}<Field label="Destination resource"><Select disabled={busy} value={resourceId} onChange={(event) => setResourceId(event.target.value)}><option value="">Select resource</option>{resources.map((resource) => <option key={resource.id} value={resource.id}>{resource.name}</option>)}</Select></Field></div></Modal>}
    {dialog === "apply" && preview && <Modal title="Confirm template assignment" placement="right" size="enrollment" showClose onDismiss={dismiss} actions={<><Button variant="ghost" disabled={busy} onClick={dismiss}>Cancel</Button><Button disabled={unavailable} onClick={() => void apply()}>Apply template</Button></>}><div className="agents-management-editor"><p>Apply v{versions?.find((version) => version.id === versionId)?.version ?? "?"} to {selectedGroup?.name ?? "the selected group"}: {preview.affected_agents} agents, {preview.created_rules} new rules, and {preview.changed_gateways} gateways will change.</p><p>You can remove the assignment later; shared rules remain.</p><ErrorText>{error}</ErrorText></div></Modal>}
    {dialog === "archive" && <Modal title="Archive policy template" danger showClose onDismiss={dismiss} actions={<><Button variant="ghost" disabled={busy} onClick={dismiss}>Cancel</Button><Button variant="danger" disabled={unavailable} onClick={() => void archive()}>Archive template</Button></>}><ErrorText>{error}</ErrorText><p>This archives the template. {selectedAssignments.length} existing assignments remain until removed separately; access is not withdrawn.</p></Modal>}
    {removing && <Modal title="Remove template assignment?" danger showClose onDismiss={() => !busy && setRemoving(null)} actions={<><Button variant="ghost" disabled={busy} onClick={() => setRemoving(null)}>Cancel</Button><Button variant="danger" disabled={unavailable} onClick={async () => { if (await removeAssignment(removing)) setRemoving(null); }}>Remove assignment</Button></>}><ErrorText>{error}</ErrorText><p>Remove v{removing.version} from {removing.group_name}? {removing.rule_count} assignment-owned rules may be withdrawn; shared rules remain.</p></Modal>}
  </div>;
}
