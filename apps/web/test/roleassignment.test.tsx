import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RoleAssignment } from "../src/components/RoleAssignment";

afterEach(cleanup);

describe("multiple role assignment", () => {
  it("removes AI administration while retaining member access", () => {
    const save = vi.fn().mockResolvedValue(undefined);
    render(<RoleAssignment email="eng@example.test" roles={["member", "ai-admin"]}
      options={["member", "ai-admin", "ai-view"]} soleOwner={false} onSave={save} />);
    fireEvent.click(screen.getByText("ai-admin", { selector: "label" }));
    fireEvent.click(screen.getByRole("button", { name: "Save roles", hidden: true }));
    expect(save).toHaveBeenCalledWith(["member"]);
  });

  it("allows adding a role to the sole owner without removing ownership", () => {
    render(<RoleAssignment email="owner@example.test" roles={["owner"]}
      options={["owner", "ai-admin"]} soleOwner onSave={vi.fn()} />);
    expect((screen.getByLabelText("owner") as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByLabelText("ai-admin") as HTMLInputElement).disabled).toBe(false);
  });
});
