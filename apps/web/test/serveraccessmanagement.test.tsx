import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ServerAccountGrants } from "../src/components/ServerAccountGrants";
import { ServerSessions } from "../src/components/ServerSessions";
import type { components } from "@tunnex/shared";
afterEach(cleanup);
const server={id:"server-1",name:"Target"} as components["schemas"]["ServerAccessServer"];
const grant=(id:string,offset:number,enabled=true,user="user-1")=>({id,server_id:server.id,account:"ubuntu",user_id:user,enabled,starts_at:new Date(Date.now()-7200000).toISOString(),expires_at:new Date(Date.now()+offset).toISOString()}) as components["schemas"]["ServerAccessGrant"];
it("hides revoked and superseded history and renews the exact expired recipient",()=>{
 const renew=vi.fn();render(<ServerAccountGrants grants={[grant("old",-10000),grant("active",60000),grant("revoked",60000,false,"user-2"),grant("expired",-10000,true,"user-3")]} servers={[server]} members={[]} groups={[]} disabled={false} onRevoke={vi.fn()} onRenew={renew}/>);
 expect(screen.getAllByRole("row")).toHaveLength(3);expect(screen.queryByText("user-2")).toBeNull();expect(screen.getByText("Active")).toBeTruthy();expect(screen.getByText("Expired")).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"Extend access"}));fireEvent.change(screen.getByLabelText("Extend duration (hours)"),{target:{value:"2"}});fireEvent.click(screen.getByRole("button",{name:"Confirm extension"}));
 const body=renew.mock.calls[0][0];expect(body).toMatchObject({server_id:server.id,account:"ubuntu",user_id:"user-3"});expect(Date.parse(body.expires_at)-Date.parse(body.starts_at)).toBeCloseTo(7200000,-2);
});
it("preserves a group recipient and cancels without granting access",()=>{
 const renew=vi.fn();const g={...grant("expired",-10000),user_id:undefined,group_id:"group-1"};render(<ServerAccountGrants grants={[g]} servers={[server]} members={[]} groups={[]} disabled={false} onRevoke={vi.fn()} onRenew={renew}/>);
 fireEvent.click(screen.getByRole("button",{name:"Extend access"}));fireEvent.click(screen.getByRole("button",{name:"Cancel"}));expect(renew).not.toHaveBeenCalled();fireEvent.click(screen.getByRole("button",{name:"Extend access"}));fireEvent.click(screen.getByRole("button",{name:"Confirm extension"}));expect(renew.mock.calls[0][0]).toMatchObject({group_id:"group-1"});expect(renew.mock.calls[0][0].user_id).toBeUndefined();
});
it("separates connection checks and paginates real sessions",()=>{
 const end=vi.fn();const sessions=Array.from({length:21},(_,i)=>({id:`session-${i}`,kind:"terminal",status:"connected",reason:"",server_id:server.id,user_id:"user-1",account:"ubuntu",created_at:new Date().toISOString(),expires_at:new Date().toISOString(),recording_enabled:false})) as components["schemas"]["ServerAccessSession"][];sessions.push({...sessions[0],id:"check-1",kind:"check",status:"passed"});
 render(<MemoryRouter><ServerSessions sessions={sessions} servers={[server]} members={[]} disabled={false} onRefresh={vi.fn()} onEnd={end} onReplay={vi.fn()} importControl={<p>Import details</p>}/></MemoryRouter>);
 expect(screen.getAllByRole("row")).toHaveLength(21);expect(screen.queryByText("check-1")).toBeNull();fireEvent.click(screen.getByRole("button",{name:"Next sessions"}));expect(screen.getAllByRole("row")).toHaveLength(2);fireEvent.click(screen.getByRole("button",{name:"End session"}));expect(end).toHaveBeenCalledWith("session-20");fireEvent.change(screen.getByLabelText("Session view"),{target:{value:"checks"}});expect(screen.getByText("check-1")).toBeTruthy();expect(screen.queryByRole("button",{name:"End session"})).toBeNull();
});
