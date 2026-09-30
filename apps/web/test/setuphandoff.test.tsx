import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
const mock = vi.hoisted(() => ({ post: vi.fn(), get: vi.fn(), setUser: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: { GET: mock.get, POST: mock.post } }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: {status:"authed",user:{id:"u1",email:"owner@example.test",must_change_password:true}},setUser:mock.setUser }) }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({org:{id:"org-a",name:"Acme"}}) }));
import ChangePassword from "../src/pages/ChangePassword";
import { ClientConnection } from "../src/components/ClientConnection";
import { SetupReturn } from "../src/components/SetupReturn";
import AcceptInvite from "../src/pages/AcceptInvite";
import Connect from "../src/pages/Connect";
function Destination() {const location=useLocation();return <p>{location.pathname+location.search}</p>;}
afterEach(cleanup);
beforeEach(()=>{vi.clearAllMocks();mock.get.mockResolvedValue({data:{public_base_url:"https://vpn.example.test"}});mock.post.mockResolvedValue({data:{}});});
describe("first connection handoff",()=>{
  it.each([["/setup?purpose=vpn","/setup?purpose=vpn"],["https://evil.example","/dashboard"],["/change-password","/dashboard"]])("password change returns safely from %s",async(next,expected)=>{
    render(<MemoryRouter initialEntries={[`/change-password?next=${encodeURIComponent(next)}`]}><Routes><Route path="/change-password" element={<ChangePassword/>}/><Route path="*" element={<Destination/>}/></Routes></MemoryRouter>);
    fireEvent.change(screen.getByLabelText("Current password"),{target:{value:"local-test-old"}});
    fireEvent.change(screen.getByLabelText("New password"),{target:{value:"local-test-new"}});
    fireEvent.change(screen.getByLabelText("Confirm new password"),{target:{value:"local-test-new"}});
    fireEvent.click(screen.getByRole("button",{name:"Set password"}));
    await screen.findByText(expected);
    expect(mock.setUser).toHaveBeenCalledWith(expect.objectContaining({must_change_password:false}));
  });
  it("does not invent a public server URL when metadata cannot be read",async()=>{
    mock.get.mockRejectedValue(new Error("unavailable"));
    render(<MemoryRouter><Connect/></MemoryRouter>);
    await screen.findByText(/Server address unavailable/);
    expect(screen.queryByRole("button",{name:"Copy server address"})).toBeNull();
  });
  it("leaves a failed password change on the password form",async()=>{
    mock.post.mockResolvedValue({error:{error:{message:"Current password is incorrect"}}});
    render(<MemoryRouter initialEntries={["/change-password?next=%2Fsetup"]}><ChangePassword/></MemoryRouter>);
    fireEvent.change(screen.getByLabelText("New password"),{target:{value:"sample-password"}});
    fireEvent.change(screen.getByLabelText("Confirm new password"),{target:{value:"sample-password"}});
    fireEvent.click(screen.getByRole("button",{name:"Set password"}));
    await screen.findByText("Current password is incorrect");
    expect(mock.setUser).not.toHaveBeenCalled();
  });
  it("keeps an expired invitation out of client onboarding",async()=>{
    mock.post.mockResolvedValue({error:{error:{message:"Invitation expired"}}});
    render(<MemoryRouter initialEntries={["/accept-invite?token=expired"]}><AcceptInvite/></MemoryRouter>);
    fireEvent.submit(screen.getByRole("button",{name:"Accept invitation"}).closest("form")!);
    await screen.findByText("Invitation expired");
    expect(screen.queryByRole("link",{name:"Sign in and connect"})).toBeNull();
  });
  it("reports failed clipboard access without claiming a copy",async()=>{
    Object.defineProperty(navigator,"clipboard",{configurable:true,value:{writeText:vi.fn().mockRejectedValue(new Error("denied"))}});
    render(<ClientConnection/>);
    fireEvent.click(await screen.findByRole("button",{name:"Copy server address"}));
    await screen.findByText(/Could not copy/);
    expect(screen.queryByText("Server address copied")).toBeNull();
  });
  it("only returns to a known setup purpose",()=>{
    const result=render(<MemoryRouter initialEntries={["/users?from=setup&purpose=vpn&setupStep=3"]}><SetupReturn/></MemoryRouter>);
    expect(screen.getByRole("link",{name:"Continue setup →"}).getAttribute("href")).toBe("/setup?purpose=vpn&step=3");
    result.unmount();
    render(<MemoryRouter initialEntries={["/users?from=setup&purpose=https://evil.example"]}><SetupReturn/></MemoryRouter>);
    expect(screen.queryByRole("link")).toBeNull();
  });
  it("accepted invitation offers client onboarding but does not sign in automatically",async()=>{
    render(<MemoryRouter initialEntries={["/accept-invite?token=sample-invite"]}><AcceptInvite/></MemoryRouter>);
    fireEvent.change(screen.getByLabelText("Your name"),{target:{value:"Sample colleague"}});
    fireEvent.change(screen.getByLabelText("Password"),{target:{value:"sample-new-password"}});
    fireEvent.click(screen.getByRole("button",{name:"Accept invitation"}));
    await waitFor(()=>expect(screen.getByRole("link",{name:"Sign in and connect"}).getAttribute("href")).toBe("/login?next=%2Fconnect"));
    expect(screen.getByRole("link",{name:"Download Client"})).toBeTruthy();
    expect(mock.setUser).not.toHaveBeenCalled();
  });
});
