import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { WorkspaceTabs } from "../src/components/WorkspaceTabs";
import { RecordingPolicyForm } from "../src/components/RecordingPolicyForm";
afterEach(cleanup);
it("identifies the query-selected workspace page without marking sibling links current",()=>{render(<MemoryRouter initialEntries={["/browser-access/terminal?view=sessions"]}><WorkspaceTabs label="Servers workspace" activeHref="/browser-access/terminal?view=sessions" items={[{href:"/browser-access/terminal",label:"Servers"},{href:"/browser-access/terminal?view=sessions",label:"Sessions"}]}/></MemoryRouter>);expect(screen.getByRole("navigation",{name:"Servers workspace"})).toBeTruthy();expect(screen.getByRole("link",{name:"Sessions"}).getAttribute("aria-current")).toBe("page");expect(screen.getByRole("link",{name:"Servers"}).hasAttribute("aria-current")).toBe(false)});
it("exposes bounded labeled recording and MFA controls and submits configured values",()=>{const save=vi.fn(async()=>{});render(<RecordingPolicyForm days={7} sessionBytes={4194304} orgBytes={67108864} mfaSeconds={900} disabled={false} onSave={save}/>);const mfa=screen.getByRole("spinbutton",{name:"Reuse two-factor verification for (minutes)"}) as HTMLInputElement;expect(mfa.min).toBe("1");expect(mfa.max).toBe("15");fireEvent.change(mfa,{target:{value:"5"}});const retention=screen.getByRole("spinbutton",{name:"Keep recordings for (days)"}) as HTMLInputElement;expect(retention.min).toBe("1");expect(retention.max).toBe("3650");fireEvent.change(retention,{target:{value:"14"}});fireEvent.click(screen.getByRole("button",{name:"Save policy"}));expect(save).toHaveBeenCalledWith({mfa_freshness_seconds:300,recording_retention_days:14,recording_max_session_bytes:4194304,recording_max_org_bytes:67108864})});

it("shows recording limits in human units and keeps the API in bytes (SA-UX-2 R4)",()=>{const save=vi.fn(async()=>{});render(<RecordingPolicyForm days={30} sessionBytes={4194304} orgBytes={1073741824} mfaSeconds={600} disabled={false} onSave={save}/>);
 expect((screen.getByRole("spinbutton",{name:"Limit per session"}) as HTMLInputElement).value).toBe("4");expect((screen.getByLabelText("Limit per session unit") as HTMLSelectElement).value).toBe("MB");
 expect((screen.getByRole("spinbutton",{name:"Limit for the organization"}) as HTMLInputElement).value).toBe("1");expect((screen.getByLabelText("Limit for the organization unit") as HTMLSelectElement).value).toBe("GB");
 expect(screen.getByText(/recording content is deleted/)).toBeTruthy();
 fireEvent.change(screen.getByLabelText("Limit per session unit"),{target:{value:"KB"}});expect(screen.getByRole("alert").textContent).toMatch(/between 64 KB and 16 MB/);
 fireEvent.change(screen.getByRole("spinbutton",{name:"Limit per session"}),{target:{value:"512"}});
 fireEvent.click(screen.getByRole("button",{name:"Save policy"}));expect(save).toHaveBeenCalledWith({mfa_freshness_seconds:600,recording_retention_days:30,recording_max_session_bytes:524288,recording_max_org_bytes:1073741824})});

it("saving another field never rounds an unedited, non-round recording limit (SA-UX-2 R4)",()=>{const save=vi.fn(async()=>{});render(<RecordingPolicyForm days={30} sessionBytes={70000} orgBytes={100000} mfaSeconds={600} disabled={false} onSave={save}/>);
 fireEvent.change(screen.getByRole("spinbutton",{name:"Keep recordings for (days)"}),{target:{value:"31"}});fireEvent.click(screen.getByRole("button",{name:"Save policy"}));
 expect(save).toHaveBeenCalledWith({mfa_freshness_seconds:600,recording_retention_days:31,recording_max_session_bytes:70000,recording_max_org_bytes:100000})});
