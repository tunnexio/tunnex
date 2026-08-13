import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { ClientApp } from "./client/ClientApp";

// ⛔ THE DESKTOP CLIENT'S OWN ENTRY POINT — no router, no AppShell, no pages.
//
// The client used to load the web SPA's index.html, which meant it mounted the router, the
// sidebar, the top bar and every dashboard screen, then hid most of it behind `isDesktop()`
// branches. That is the makeshift this replaces: the client is not a small dashboard, and the
// wireframe's own block agrees — it specifies ONE window with four regions and nothing else.
//
// Tokens are shared (index.css); components are its own. That is Item A's ruling.
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ClientApp />
  </StrictMode>,
);
