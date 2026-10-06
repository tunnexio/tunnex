# Browser terminal frontend qualification

Local evidence dated 2026-10-05, on the uncommitted `feature/browser-access` worktree. This record qualifies the checks below; it does not accept the complete Server Access epic, production capacity, recovery, or a release.

## Exact supported build engine

The repository requires Node `>=24.21.0 <25`. The [official release index](https://nodejs.org/dist/index.json) lists Node **v24.21.0**, released 2026-09-07, with a Darwin arm64 tarball. Downloaded into an owned temporary directory without a global installation:

- Runtime: `/private/tmp/tunnex-sa-node-24.21.0/node-v24.21.0-darwin-arm64/bin/node`
- Archive: `node-v24.21.0-darwin-arm64.tar.gz`
- SHA256: `bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057`
- Checksum matched [the official HTTPS SHASUMS256 manifest](https://nodejs.org/dist/v24.21.0/SHASUMS256.txt) before extraction. This is HTTPS-source and checksum verification; a separate OpenPGP signature verification was not performed.
- `node --version` returned `v24.21.0`.
- pnpm executable: `/Users/pawangupta/.nvm/versions/node/v22.23.2/bin/pnpm`; PATH selects the exact Node runtime above, and no engine-strict override was used.

## Executed gates

| Gate | Evidence |
|---|---|
| Full web suite | 162 test files passed; 2050 tests passed plus 2 expected failures; 83.19 seconds. This run preceded the four additional qualification cases and narrow network-error cancellation fix below; the final coordinator integration gate must cover the final source. |
| Full web suite with qualification cases | 163 files passed; 2053 tests passed plus 2 expected failures; 82.21 seconds. This run included the new navigation/policy and access-denied replay cases but started before the last network-error fix/test. |
| Typecheck | `pnpm --dir apps/web typecheck` passed under Node v24.21.0, including a final rerun after the network-error fix. |
| Production build | `pnpm --dir apps/web build` passed under Node v24.21.0. The existing aggregate JS chunk remains about 2.13 MB; the >500 kB warning is not a terminal performance qualification. |
| Focused terminal, recording storage, replay and screen census | 5 files / 23 tests passed under the exact engine, including the two new qualification cases and both replay-loss regressions. |
| Additional replay withdrawal regression | Denied access and network-error metadata polls clear visible content, remove replay controls and cancel queued output callbacks. A confirmed network-error cancellation gap was fixed locally and qualified by a dedicated regression. |

Logs remain local at `/private/tmp/tunnex-sa-web-exact-engine-tests.txt`, `/private/tmp/tunnex-sa-web-exact-engine-tests-final.txt`, `/private/tmp/tunnex-sa-web-exact-engine-typecheck.txt`, `/private/tmp/tunnex-sa-web-exact-engine-build.txt` and `/private/tmp/tunnex-sa-web-qualification-focused-final.txt`. Generated build outputs and logs are not release artifacts.

## Accessibility and rendering boundaries

Automated DOM evidence now verifies that query-selected workspace navigation identifies exactly one current page, recording/MFA controls have accessible labels and bounded values, configured policy values reach the request handler, and replay authority withdrawal clears content and controls. Existing terminal tests preserve the Strict Mode single-use WebSocket admission and failed End behavior. Ordered replay tests wait for parsed output before applying resize and prevent superseded seek callbacks from continuing.

These tests do not establish a screen-reader certification, WCAG conformance, keyboard-only end-to-end completion, browser rendering, or physical mobile-device support. xterm screenReaderMode is enabled in both live terminal and replay, but that setting alone is not assistive-technology qualification.

The coordinator owns the authenticated admin/member browser walkthrough and final responsive screenshots. This agent created a separate Chrome-extension tab which reached the local CP sign-in page; it did not sign in, log out, alter credentials, or reuse the coordinator's active terminal. Therefore that tab supplies no authenticated terminal or responsive evidence.

| Browser/device surface | Actual qualification boundary |
|---|---|
| Coordinator's existing local Chromium browser | Earlier real SSH/PTY member evidence is recorded in the development evidence. During this qualification the coordinator reported a 390×844 viewport with viewport/document/main widths all 390 px, confirming no page-level horizontal overflow on that observed Servers view. Final updated admin/settings/replay walkthrough remains coordinator-owned. |
| Chrome extension, separate new tab | Local route reaches sign-in; authenticated terminal not exercised by this agent. |
| Firefox / Safari | Not exercised. |
| Physical iOS / Android device | Not exercised. Responsive desktop viewport emulation must not be called physical-device qualification. |
| Screen reader | Not exercised. |

For documented responsive checks, obtain `const viewport = await browser.capabilities.get("viewport")`, call `await viewport.set({width:390,height:844})`, inspect rendered DOM and screenshots in the coordinator-owned tab, and call `await viewport.reset()` in a finally block. The override is browser-scoped; coordinate it with other active tabs. No undocumented device-emulation API is assumed.

## Coordinator final rendered and keyboard checks

Final full `pnpm --filter @tunnex/web verify` after the network-error replay fix passed under Node24.21.0: 163 files,2054 passed and2 expected failures,77.52 seconds; typecheck/build passed. Log `/private/tmp/sa-web-final-verify.log`.

Authenticated Chromium at390×844 showed no page overflow on Servers, Register server (366px dialog,364px scroll width) and Settings (document width390px). Settings at768×1024 also had document width768px. The settings screenshot `/private/tmp/tunnex-sa0-spike/mobile-terminal-settings.png` was visually inspected. The browser viewport override was reset. Registration Tab moved focus from Close to the first input; Escape dismissed the dialog and restored the Register server trigger. This is narrow keyboard/viewport proof, not screen-reader or physical-device certification. Real signedSSO terminal rendering is in the identity evidence.
