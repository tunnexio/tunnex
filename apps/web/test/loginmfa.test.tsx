import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { setUser, post } = vi.hoisted(() => ({ setUser: vi.fn(), post: vi.fn() }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ setUser }) }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async () => ({ data: { sso_providers: [] } })),
      POST: post,
    },
  };
});

import Login from "../src/pages/Login";

describe("MFA recovery login journey", () => {
  it("accepts a recovery code and mints the session once", async () => {
    post.mockReset();
    post.mockResolvedValueOnce({ data: { mfa_required: true, challenge: "c1", recovery_codes_remaining: 3 } });
    post.mockResolvedValueOnce({ data: { id: "u1", email: "a@example.com" } });
    render(<MemoryRouter initialEntries={["/login"]}><Login /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "a@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
    await screen.findByText(/or a recovery code/i);
    fireEvent.change(screen.getByLabelText("Code"), { target: { value: "RECOVERY-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(setUser).toHaveBeenCalledWith({ id: "u1", email: "a@example.com" }));
    expect(post).toHaveBeenLastCalledWith("/api/v1/auth/mfa/verify", { body: { challenge: "c1", code: "RECOVERY-1" } });
  });
});
