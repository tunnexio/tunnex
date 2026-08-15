import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentProfileEditor, type AgentProfileEditorValue } from "../src/components/AgentProfileEditor";

const metadata: AgentProfileEditorValue = { environment: "prod", runtime: "python", labels: { team: "sec" } };

describe("AgentProfileEditor", () => {
  afterEach(() => cleanup());
  it("saves metadata without a lifecycle/status payload", () => {
    const onSaveMetadata = vi.fn();
    render(<AgentProfileEditor value={{ ...metadata, status: "pending" }} canManageLifecycle={false} onSaveMetadata={onSaveMetadata} onLifecycleChange={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Environment"), { target: { value: "staging" } });
    fireEvent.click(screen.getByRole("button", { name: "Save metadata" }));
    expect(onSaveMetadata).toHaveBeenCalledWith({ environment: "staging", runtime: "python", labels: { team: "sec" } });
    expect(onSaveMetadata.mock.calls[0][0]).not.toHaveProperty("status");
    expect(screen.getByText(/awaiting approval/i)).toBeTruthy();
  });

  it("rejects invalid labels accessibly without saving", () => {
    const onSaveMetadata = vi.fn();
    render(<AgentProfileEditor value={{ ...metadata, labels: {}, status: "active" }} canManageLifecycle={true} onSaveMetadata={onSaveMetadata} onLifecycleChange={vi.fn()} />);
    fireEvent.change(screen.getByLabelText(/Labels/), { target: { value: "[]" } });
    fireEvent.click(screen.getByRole("button", { name: "Save metadata" }));
    expect(screen.getByRole("alert").textContent).toMatch(/JSON object/);
    expect(onSaveMetadata).not.toHaveBeenCalled();
  });

  it("emits only active/suspended lifecycle intent and no revoke/pending controls", () => {
    const onLifecycleChange = vi.fn();
    render(<AgentProfileEditor value={{ ...metadata, status: "active" }} canManageLifecycle={true} onSaveMetadata={vi.fn()} onLifecycleChange={onLifecycleChange} />);
    fireEvent.click(screen.getByRole("button", { name: "Suspend agent" }));
    expect(onLifecycleChange).toHaveBeenCalledWith("suspended");
    expect(screen.queryByRole("button", { name: /revoke|resume/i })).toBeNull();
  });
});
