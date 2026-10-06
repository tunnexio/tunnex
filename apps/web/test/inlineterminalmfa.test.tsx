import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { InlineTerminalMfa } from "../src/components/InlineTerminalMfa";
const post=vi.hoisted(()=>vi.fn());
vi.mock("../src/lib/api",()=>({api:{POST:post},apiErrorMessage:()=>"Invalid code"}));
vi.mock("../src/components/MfaSettings",()=>({MfaSettings:()=>null}));
afterEach(()=>{cleanup();post.mockReset()});
it("verifies inline and continues the blocked action once",async()=>{
 post.mockResolvedValue({data:{ok:true}});const next=vi.fn();
 render(<InlineTerminalMfa action="Check ubuntu" onVerified={next} onCancel={()=>{}}/>);
 fireEvent.change(screen.getByLabelText("Authenticator or recovery code"),{target:{value:"123456"}});
 fireEvent.click(screen.getByRole("button",{name:"Verify and continue"}));
 await waitFor(()=>expect(next).toHaveBeenCalledTimes(1));
 expect(post).toHaveBeenCalledWith("/api/v1/auth/mfa/step-up",{body:{code:"123456"}});
 expect(screen.getByText(/15 minutes/)).toBeTruthy();
});
it("a rejected code never continues the blocked action",async()=>{
 post.mockResolvedValue({error:{error:{message:"Invalid code"}}});const next=vi.fn();
 render(<InlineTerminalMfa action="Check ubuntu" onVerified={next} onCancel={()=>{}}/>);
 fireEvent.change(screen.getByLabelText("Authenticator or recovery code"),{target:{value:"bad"}});
 fireEvent.click(screen.getByRole("button",{name:"Verify and continue"}));
 await screen.findByText("Invalid code");expect(next).not.toHaveBeenCalled();
});
it("cancel does not verify or resume the action",()=>{
 const cancel=vi.fn(),next=vi.fn();render(<InlineTerminalMfa action="Sync accounts" onVerified={next} onCancel={cancel}/>);
 fireEvent.click(screen.getByRole("button",{name:"Cancel verification"}));
 expect(cancel).toHaveBeenCalledTimes(1);expect(post).not.toHaveBeenCalled();expect(next).not.toHaveBeenCalled();
});
