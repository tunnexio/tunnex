import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api: { GET: mocks.get, POST: mocks.post, PUT: mocks.put, DELETE: mocks.del }, apiErrorMessage: (_: unknown, fallback: string) => fallback }));
import { SavedSSHKeyPicker } from "../src/components/SavedSSHKeyPicker";
const key = { id: "one", name: "Laptop", public_key: "ssh-ed25519 AAAA\n", fingerprint: "SHA256:fixture", is_default: true };
beforeEach(() => { vi.clearAllMocks(); mocks.get.mockResolvedValue({ data: { items: [key] } }); mocks.del.mockResolvedValue({}); mocks.put.mockResolvedValue({}); });
afterEach(cleanup);
it("selects the default and merges manual keys", async () => {
 const change = vi.fn(); render(<SavedSSHKeyPicker orgId="org" value="" onChange={change} />);
 await screen.findByText("Laptop · Default"); expect(change).toHaveBeenLastCalledWith("ssh-ed25519 AAAA");
 fireEvent.change(screen.getByLabelText("SSH public keys"), { target: { value: "ssh-rsa BBBB" } }); expect(change).toHaveBeenLastCalledWith("ssh-ed25519 AAAA\nssh-rsa BBBB");
 fireEvent.click(screen.getByRole("checkbox")); expect(change).toHaveBeenLastCalledWith("ssh-rsa BBBB");
});
it("removes only the registry entry and explains existing access", async () => {
 const change = vi.fn(); render(<SavedSSHKeyPicker orgId="org" value="" onChange={change} />); await screen.findByText("Laptop · Default");
 fireEvent.click(screen.getByRole("button", { name: "Remove Laptop" })); await waitFor(() => expect(screen.queryByRole("checkbox")).toBeNull());
 expect(mocks.del).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/saved-ssh-keys/{keyId}", { params: { path: { orgId: "org", keyId: "one" } } }); expect(change).toHaveBeenLastCalledWith(""); expect(screen.getByText(/existing sandbox access unchanged/)).toBeTruthy();
});
it("keeps manual input available when loading fails", async () => {
 mocks.get.mockResolvedValue({ error: {} }); const change = vi.fn(); render(<SavedSSHKeyPicker orgId="org" value="" onChange={change} />);
 await screen.findByRole("alert"); fireEvent.change(screen.getByLabelText("SSH public keys"), { target: { value: "ssh-ed25519 manual" } }); expect(change).toHaveBeenLastCalledWith("ssh-ed25519 manual");
});
it("saves a named key then selects its returned normalized public key", async () => {
 mocks.get.mockResolvedValue({ data: { items: [] } }); mocks.post.mockResolvedValue({ data: key }); const change = vi.fn(); render(<SavedSSHKeyPicker orgId="org" value="" onChange={change} />);
 await waitFor(() => expect(screen.queryByRole("status")).toBeNull()); fireEvent.click(screen.getByText("Save a named key")); fireEvent.change(screen.getByLabelText("Key name"), { target: { value: "Laptop" } }); fireEvent.change(screen.getByLabelText("Public key to save"), { target: { value: key.public_key } }); fireEvent.click(screen.getByText("Save & select")); await screen.findByText("Laptop · Default"); expect(change).toHaveBeenLastCalledWith(key.public_key.trim());
});
it("restores saved selections when returning to the access step", async () => {
 const change = vi.fn(); render(<SavedSSHKeyPicker orgId="org" value={key.public_key.trim()+"\nssh-rsa manual"} onChange={change} />); await screen.findByText("Laptop · Default");
 expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(true); expect((screen.getByLabelText("SSH public keys") as HTMLTextAreaElement).value).toBe("ssh-rsa manual");
});
it("changes the default without changing the current selection", async () => {
 mocks.get.mockResolvedValue({ data: { items: [key, { ...key, id: "two", name: "Desktop", is_default: false, public_key: "ssh-rsa BBBB" }] } });
 const change = vi.fn(); render(<SavedSSHKeyPicker orgId="org" value="" onChange={change} />); await screen.findByText("Desktop"); fireEvent.click(screen.getByText("Make default")); await screen.findByText("Desktop · Default"); expect(change).toHaveBeenLastCalledWith(key.public_key.trim());
});
it("does not overwrite manual input entered while keys are loading", async () => {
 let resolve!: (value: unknown) => void; mocks.get.mockReturnValue(new Promise(r => { resolve = r; })); const change = vi.fn(); render(<SavedSSHKeyPicker orgId="org" value="" onChange={change} />);
 fireEvent.change(screen.getByLabelText("SSH public keys"), { target: { value: "ssh-rsa manual" } }); resolve({ data: { items: [key] } }); await screen.findByText("Laptop · Default"); expect(change).toHaveBeenLastCalledWith("ssh-rsa manual"); expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false);
});
