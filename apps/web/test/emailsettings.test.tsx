import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { EmailDeliverySettings } from "../src/components/EmailDeliverySettings";
const mocks = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), POST: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: mocks }));
const saved = { enabled:true, host:"smtp.example.test", port:587, from:"noreply@example.test", username:"mailer", password_configured:true, source:"installer" as const, revision:0 };
const show = (canEdit=true) => render(<EmailDeliverySettings canEdit={canEdit} email="admin@example.test" />);
afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); mocks.GET.mockResolvedValue({data:saved}); });
describe("server email settings", () => {
  it("prefills installation values without fetching or rendering a password; sends candidate only to the server-fixed recipient", async () => {
    mocks.POST.mockResolvedValue({data:{accepted:true}}); show();
    expect((await screen.findByRole("textbox", {name:"SMTP server"}) as HTMLInputElement).value).toBe(saved.host);
    expect(screen.queryByLabelText("New SMTP password")).toBeNull();
    expect(screen.getByRole("option", {name:"Keep saved password"})).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Sender email"), {target:{value:"new@example.test"}});
    fireEvent.click(screen.getByRole("button",{name:"Send test email"}));
    await screen.findByText(/provider accepted the test email/);
    expect(mocks.POST).toHaveBeenCalledWith("/api/v1/admin/email-settings/test", {body:expect.objectContaining({from:"new@example.test",password_action:"keep",revision:0})});
    const body=mocks.POST.mock.calls[0][1].body;
    expect(body).not.toHaveProperty("to"); expect(body.password).toBeUndefined(); expect(mocks.PUT).not.toHaveBeenCalled();
  });
  it("shows failed test separately, retains draft and saved revision, and clears a replacement secret after saving", async () => {
    mocks.POST.mockResolvedValue({error:{error:{code:"smtp_test_failed",message:"SMTP test failed."}}});
    mocks.PUT.mockResolvedValue({data:{...saved,source:"server",revision:1}}); show();
    await screen.findByRole("textbox",{name:"SMTP server"});
    fireEvent.change(screen.getByLabelText("Password action"),{target:{value:"replace"}});
    fireEvent.change(screen.getByLabelText("New SMTP password"),{target:{value:"demo-secret"}});
    fireEvent.click(screen.getByRole("button",{name:"Send test email"}));
    await screen.findByText("SMTP test failed.");
    expect(mocks.PUT).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button",{name:"Save changes"}));
    await screen.findByText(/Email settings saved/);
    expect(mocks.PUT.mock.calls[0][1].body).toMatchObject({revision:0,password_action:"replace",password:"demo-secret"});
    expect(screen.queryByLabelText("New SMTP password")).toBeNull();
    expect((screen.getByRole("button",{name:"Save changes"}) as HTMLButtonElement).disabled).toBe(true);
  });
  it("does not invent defaults after a failed read and supports retry", async () => {
    mocks.GET.mockResolvedValueOnce({error:{error:{message:"Settings unavailable"}}}); show();
    await screen.findByText("Settings unavailable");
    expect(screen.queryByRole("button",{name:"Save changes"})).toBeNull();
    fireEvent.click(screen.getByRole("button",{name:"Retry email settings"}));
    await screen.findByRole("textbox",{name:"SMTP server"});
  });
  it("requires the edit permission and prevents duplicate submissions", async () => {
    const {rerender}=show(false); await screen.findByRole("textbox",{name:"SMTP server"});
    expect((screen.getByRole("button",{name:"Send test email"}) as HTMLButtonElement).disabled).toBe(true);
    rerender(<EmailDeliverySettings canEdit email="admin@example.test"/>);
    let complete:(v:unknown)=>void=()=>{}; mocks.POST.mockImplementation(()=>new Promise(resolve=>{complete=resolve;}));
    fireEvent.click(screen.getByRole("button",{name:"Send test email"}));
    fireEvent.click(screen.getByRole("button",{name:"Sending test…"}));
    expect(mocks.POST).toHaveBeenCalledTimes(1);
    complete({data:{accepted:true}}); await waitFor(()=>expect(screen.queryByText("Sending test…")).toBeNull());
  });
});
