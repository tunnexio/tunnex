import {afterEach,expect,it} from "vitest";
import {cleanup,render,screen} from "@testing-library/react";
import {SandboxCandidateProfiles,ImageProfileDetails} from "../src/components/SandboxImageProfiles";
import type {SandboxImageProfile} from "../src/lib/api";
afterEach(cleanup);
const profile:SandboxImageProfile={name:"Minimal Alpine",distro:"Alpine (musl)",architecture:"amd64",image_digest:"sha256:fixture",config_digest:"sha256:config",compressed_image_bytes:12000000,unpacked_image_bytes:32000000,idle_memory_bytes:3000000,evidence_context:"Docker emulation; native rootless RAM not qualified",measured_at:"2026-10-03",included_tools:["OpenSSH/SFTP","WireGuard"],excluded_tools:["Python","Node"],compatibility:"musl compatibility requires verification",qualification:"candidate",emulated:true,measurement_memory_cap_bytes:134217728,measurement_workspace_cap_bytes:268435456};
it("shows candidate measurements without a launch action or configured-resource claim",()=>{
 render(<SandboxCandidateProfiles profiles={[profile]}/>);
 expect(screen.getByText("Awaiting server verification")).toBeTruthy();expect(screen.getByText(/Emulated measurement/)).toBeTruthy();expect(screen.getByText("12.0 MB")).toBeTruthy();expect(screen.getByText(/These are test bounds/)).toBeTruthy();expect(screen.getByText(/Not included: Python, Node/)).toBeTruthy();expect(screen.queryByRole("button")).toBeNull();expect(screen.queryByRole("link")).toBeNull();expect(screen.queryByRole("option")).toBeNull();
});
it("leaves unknown image measurements absent",()=>{render(<ImageProfileDetails/>);expect(screen.getByText(/not measured/)).toBeTruthy();expect(screen.queryByText("12.0 MB")).toBeNull()});

it("groups architectures into one profile choice",()=>{render(<SandboxCandidateProfiles profiles={[profile,{...profile,architecture:"arm64",image_digest:"sha256:arm64",emulated:false}]}/>);expect(screen.getAllByRole("heading",{name:"Minimal Alpine"})).toHaveLength(1);expect(screen.getByText("Measurements for arm64")).toBeTruthy();expect(screen.getByText("Measurements for amd64 (emulated)")).toBeTruthy()});

it("keeps profiles and measurement provenance collapsed until requested",()=>{
 const {container}=render(<SandboxCandidateProfiles profiles={[profile]}/>);
 const rows=container.querySelectorAll('details.sb-profile-row');expect(rows).toHaveLength(1);expect((rows[0] as HTMLDetailsElement).open).toBe(false);
 expect((container.querySelector('details.sb-measurements') as HTMLDetailsElement).open).toBe(false);
 expect(container.querySelector('.sb-card-grid')).toBeNull();
});
