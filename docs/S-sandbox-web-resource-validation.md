# Sandbox UI resource validation

Source preserved at content tip9e3a57d, followed by backend-only cleanup edits. Pinned tool versions: Node24.21.0-alpine, pnpm10.34.5, Vite6.4.3. Dependencies installed only in isolated worktree. Production Vite configuration is unchanged (`sourcemap:true`).

Docker Desktop Linux aarch64:10 CPUs, total memory8217059328 bytes, cgroupv2, builtin seccomp. Host shell limits: processes2666, file descriptors1048575, stack8176KiB; address/data/CPU limits unlimited. Read-only Docker stats showed many unrelated services; the two largest were approximately2.39GiB and922MiB. Their settings/state were never changed. Total memory is not currently free memory; stats are a momentary sample, not a promise of available headroom.

| Invocation | Limits | Result | Peak bytes | OOM kill |
|---|---|---|---:|---:|
| Original bounded production Vite after component tests |1 CPU; memory/swap1610612736; JS heap1024MiB |655 modules transformed; killed rendering chunks; exit137, Docker OOMKilled=true |960331776 |1 |
| Earlier full typecheck |same container bounds |pass |945278976 |0 |
| Follow-up combined typecheck/tests |same bounds; automatically removed |exit137 before results; cause unconfirmed |unavailable |unavailable |
| Minimal Vite validation |1 CPU; memory/swap1073741824; JS heap768MiB; GOMAXPROCS=1; sourcemap=false; minify=false |pass,655 modules,16.13s |785162240 |0 |
| Final component tests |1 worker/CPU; memory/swap536870912; JS heap384MiB |all3 pass,2.71s |245837824 |0 |
| Final full typecheck |1 CPU; memory/swap1073741824; JS heap768MiB |pass |800292864 |0 |

Retained task-owned stopped containers have names `tunnex-sandbox-ui-bounded-20261002`, `tunnex-sandbox-tsc-bounded-20261002`, `tunnex-sandbox-ui-minimal-20261002`, `tunnex-sandbox-ui-tests-final-20261002`, `tunnex-sandbox-tsc-final-20261002`. Resource peaks/events are in their logs where recorded. Minimal output is outside the repository at `../validation-artifacts/web/index.html`; no generated validation bundle is committed.

The successful minimal build was invoked from apps/web with `node --input-type=module -e 'import { build } from "vite"; await build({build:{sourcemap:false,minify:false,outDir:"dist-validation"}});'` inside the bounded container. This lowers source-map/minification work and limits Go/esbuild concurrency; it is not the unchanged production command. No unchanged heavy failure was retried. Normal production source-map/minification validation remains unpassed. No user decision is needed to use the passing minimal build for local code validation. If the unchanged production artifact is required now, the smallest decision is additional build memory or approval of a source-map-disabled production profile; neither resource settings nor production configuration was altered.

Visual QA remains unrun for a precise capability reason: callable tools provide shell, view_image and open_in_codex (open a browser tab), but no Node REPL, browser-client bootstrap or discovery tool. The browser skill requires that REPL to inspect/click/screenshot the opened browser. This says nothing about other executors or browser UI being generally unavailable. No browser-control fallback or environment switch was attempted.
