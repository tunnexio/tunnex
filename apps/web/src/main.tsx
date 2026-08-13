import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
// Self-hosted brand fonts (bundled by Vite — no CDN, works fully offline/on-prem).
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import App from "./App";
import { LayoutCapabilityProvider } from "./components/ComposeGate";
import { MotionProvider } from "./components/MotionProvider";
import { ToastProvider } from "./components/Toasts";
// S14.1: the design tokens' CSS custom properties. GENERATED from packages/shared/src/tokens.ts by
// `make generate` and drift-guarded by `make generate-check`. Imported FIRST so `:root` carries the variables
// before any Tailwind utility resolves them.
import "../../../packages/shared/generated/tokens.css";
import "./index.css";

// ⛔ THE DESKTOP TRANSPORT BOOTSTRAP IS GONE (S14.20 step 4). It read the configured server origin
// off the bridge before the first request, because this entry used to be what the Electron client
// loaded. It loads `client.html` now, so this file only ever runs in a BROWSER — where `desktop()`
// is null and the whole block was a no-op that still cost an `await` before first paint.
//
// ⚠ The client needs no origin at all: `ClientApp` talks to the bridge and imports no HTTP client,
// so there is nothing to point anywhere. Verified before this was removed, not assumed.
function boot() {
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <BrowserRouter>
        {/* S14.2: the viewport is measured ONCE, here, and handed down as a CAPABILITY. No screen reads a
            pixel width; screens declare what they compose and let the gate decide. */}
        <LayoutCapabilityProvider>
          {/* S14.3 slice B: the motion preference and the toast surface are both APP-EDGE concerns —
              measured/owned once, consumed everywhere, never re-derived per screen. */}
          <MotionProvider>
            <ToastProvider>
              <App />
            </ToastProvider>
          </MotionProvider>
        </LayoutCapabilityProvider>
      </BrowserRouter>
    </React.StrictMode>,
  );
}

void boot();
