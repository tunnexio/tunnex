import { useState } from "react";
import { afterEach, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { PrivateDNSLANListener } from "../src/components/PrivateDNSLANListener";
afterEach(cleanup);
it("keeps public forwarding off until explicit opt-in and clears it when disabled",()=>{
 function Draft(){const [listener,setListener]=useState<{address:string;interface:string;allowed_sources:string[];default_upstreams?:string[]}|undefined>({address:"192.168.1.39",interface:"eth0",allowed_sources:["192.168.1.0/24"]});return <><PrivateDNSLANListener value={listener} onChange={setListener} profileIndex={0}/><output>{JSON.stringify(listener)}</output></>}
 render(<Draft/>);
 const toggle=screen.getByRole("checkbox",{name:"Resolve other domains"}) as HTMLInputElement;
 expect(toggle.checked).toBe(false);
 expect(screen.queryByLabelText("Profile 1 public DNS upstreams")).toBeNull();
 expect(screen.getByText(/If no profile on this same DNS address and interface enables other-domain DNS for your client range/)).toBeTruthy();
 fireEvent.click(toggle);
 fireEvent.change(screen.getByLabelText("Profile 1 public DNS upstreams"),{target:{value:"1.1.1.1, 8.8.8.8"}});
 expect(screen.getByRole("status").textContent).toContain('"default_upstreams":["1.1.1.1","8.8.8.8"]');
 expect(screen.getByText(/After testing private and public DNS/)).toBeTruthy();
 fireEvent.click(toggle);
 expect(screen.getByRole("status").textContent).not.toContain("default_upstreams");
});
