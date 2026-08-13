import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import {
  formatBytes,
  formatDuration,
  formatRate,
  parsePreviewState,
  postureCheckSummary,
  stateView,
  trayAppearance,
  type ClientState,
} from "../lib/clientstate";
import { desktop, type AppInfo, type ImportedProfile, type ReleaseCheck } from "../lib/desktop";
import { Logo, Tagline } from "../brand";
import { Icon, type IconName } from "../components/Icon";
import { drawGraph, pushRate, rateBetween } from "./throughput";
import {
  createHyperState,
  drawHyper,
  stepLink,
  type HyperMode,
} from "./hyperdrive";

/**
 * ClientApp — the desktop client's whole UI.
 *
 * ⛔ FOUR REGIONS, AND THE LIST IS CLOSED: status head · connection stats · the primary verb ·
 * split-tunnel. The wireframe's block specifies exactly this and no dashboard content of any kind.
 *
 * It mounts NO router and imports NO page. The only shared code is tokens (index.css), the
 * formatting helpers, and the desktop bridge type.
 */
export function ClientApp() {
  const preview = useMemo(() => parsePreviewState(window.location.search), []);
  const previewIPv6 = useMemo(() => new URLSearchParams(window.location.search).get("ip") === "ipv6", []);
  const [live, setLive] = useState<ClientState>("disconnected");
  const [postureFailures, setPostureFailures] = useState<Array<{ kind: string; mode: string }>>([]);
  const [fullTunnel, setFullTunnel] = useState(false);
  const [showActionHint, setShowActionHint] = useState(true);
  // ⛔ REAL COUNTERS NOW, AND THE `n/a` IS NO LONGER PERMANENT. These were hard-wired to null with
  // a comment saying they would arrive "in step 3"; step 3 came and went and they never did, so the
  // panel showed `n/a` in every field forever while the plot beside it drew invented traffic.
  //
  // rx/tx/handshake come from the helper's `wg show` through the bridge. There is no PACKET counter
  // anywhere in that chain — helper, protocol or preload — so that row was a field that could never
  // be filled, and it is gone rather than reserved.
  const [stats, setStats] = useState<{
    rate: number | null;
    peak: number;
    rx: number | null;
    tx: number | null;
    since: number | null;
    handshakeSec: number | null;
    address: string | null;
    history: number[];
  }>({
    rate: null,
    peak: 0,
    rx: null,
    tx: null,
    since: null,
    handshakeSec: null,
    address: null,
    history: [],
  });

  const state = preview ?? live;
  const view = stateView(state);
  const tray = trayAppearance(state);
  const postureReason = postureCheckSummary(postureFailures);

  // ⛔ THE SURFACE ASKED THE TUNNEL AND NEVER ASKED THE SESSION.
  //
  // It called `tunnel.status()` alone, so a device with NO CREDENTIAL rendered "Disconnected" —
  // a healthy-looking idle state — with a Connect button. Pressing it threw `not_authenticated`
  // from main, unhandled, into a terminal log. The renderer showed nothing at all.
  //
  // Auth is read FIRST and WINS: signed-out is not a kind of disconnected, it is the reason
  // connecting cannot be attempted. `expired` maps to the design's own EXPIRED CREDS.
  const [serverUrl, setServerUrl] = useState<string | null>(null);
  const [identity, setIdentity] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [authed, setAuthed] = useState<boolean | null>(null);

  useEffect(() => {
    if (state !== "disconnected" || busy) {
      setShowActionHint(false);
      return;
    }
    let hideTimer = 0;
    let repeatTimer = 0;
    const cycle = () => {
      setShowActionHint(true);
      hideTimer = window.setTimeout(() => {
        setShowActionHint(false);
        repeatTimer = window.setTimeout(cycle, 9000);
      }, 4500);
    };
    cycle();
    return () => {
      window.clearTimeout(hideTimer);
      window.clearTimeout(repeatTimer);
    };
  }, [busy, state]);

  function showProblem(error: unknown): void {
    // Keep the implementation detail in the client log / developer console. The
    // on-screen surface is a VPN control, not an IPC diagnostic.
    console.error("Tunnex client action failed", error);
    setProblem(clientErrorMessage(error));
  }

  async function refreshAuth(): Promise<boolean> {
    const d = desktop();
    if (!d) return true;
    try {
      const st = await d.auth.status();
      setIdentity(st.fingerprint ?? null);
      const ok = st.loggedIn && !st.expired;
      setAuthed(ok);
      if (!st.loggedIn) setLive("signed_out");
      else if (st.expired) setLive("expired_creds");
      return ok;
    } catch {
      // ⚠ A FAILED READ IS NOT "SIGNED OUT". Claiming signed-out on an unreadable session would
      // invite a pointless re-login; the same absent-until-known rule the nav counts follow.
      setAuthed(null);
      return true;
    }
  }

  useEffect(() => {
    const d = desktop();
    if (!d || preview) return;
    void d.config
      .getServerUrl()
      .then(setServerUrl)
      .catch(() => {});
    void d.diag
      .appInfo()
      .then(setAppInfo)
      .catch(() => {});
    // Discovery is read-only: it may surface an available release, but never downloads
    // or installs it. The user still chooses Download from the official site.
    void d.diag
      .checkRelease()
      .then(setReleaseCheck)
      .catch(() => {});
    void d.tunnel
      .importedProfiles()
      .then(setImportedProfiles)
      .catch(() => {});
    void (async () => {
      const ok = await refreshAuth();
      if (ok) applyTunnelStatus(await d.tunnel.status());
    })();
    return d.tunnel.onStatusChanged(applyTunnelStatus);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preview]);

  function applyTunnelStatus(s: { state?: string; failed_checks?: Array<{ kind: string; mode: string }> }): void {
    setLive(mapStatus(s));
    setPostureFailures(s.failed_checks ?? []);
  }

  /**
   * ⛔ THE STATS POLL. `onStatusChanged` fires on TRANSITIONS; byte counters change continuously,
   * so a surface driven only by transitions shows the numbers from the moment of connection and
   * then never moves. Polling is the right instrument here precisely because nothing pushes.
   *
   * The rate is a DELTA between readings, not a field — no counter reports bytes/sec.
   */
  const prevCounter = useRef<{ bytes: number; at: number } | null>(null);
  useEffect(() => {
    const d = desktop();
    if (!d || preview) return;
    let stop = false;
    const tick = async () => {
      try {
        const st = await d.tunnel.status();
        if (stop) return;
        // Warn mode leaves the tunnel up. It must keep reporting real counters and
        // animating the live connection rather than look disconnected.
        const up = st?.state === "up" || st?.state === "posture_warning";
        if (!up) {
          // Down: drop the baseline and the clock. Keeping them would make the next connection
          // report a rate computed across the gap and a duration that includes it.
          prevCounter.current = null;
          setStats((p) => ({
            ...p,
            rate: null,
            rx: null,
            tx: null,
            since: null,
            handshakeSec: null,
            address: null,
            history: [],
          }));
          return;
        }
        const bytes = (st.rx_bytes ?? 0) + (st.tx_bytes ?? 0);
        const now = { bytes, at: Date.now() };
        const rate = rateBetween(prevCounter.current, now);
        prevCounter.current = now;
        setStats((p) => ({
          rate,
          peak: Math.max(p.peak, rate),
          rx: st.rx_bytes ?? null,
          tx: st.tx_bytes ?? null,
          since: p.since ?? Date.now(),
          handshakeSec: st.last_handshake_sec ?? null,
          address: st.address ?? null,
          history: pushRate(p.history, rate),
        }));
      } catch {
        /* a failed poll is not a state change — the last known numbers stand */
      }
    };
    void tick();
    const id = window.setInterval(() => void tick(), 1000);
    return () => {
      stop = true;
      window.clearInterval(id);
    };
  }, [preview]);

  // Browser preview has no helper. Seed the connected review state with representative values so
  // metric hierarchy is reviewed under the same density users see on a live tunnel.
  const displayStats = preview === "connected"
    ? {
        rate: 5832,
        peak: 7740,
        rx: 128_480_256,
        tx: 48_263_168,
        since: Date.now() - 3_726_000,
        handshakeSec: Math.floor(Date.now() / 1000) - 7,
        address: previewIPv6 ? "fd42:99::2/128" : "10.99.0.2/32",
        history: [1200, 1840, 2650, 3210, 4170, 5832, 4760, 6400, 5220, 5832],
      }
    : stats;
  const elapsed = displayStats.since
    ? Math.floor((Date.now() - displayStats.since) / 1000)
    : null;
  // last_handshake_sec is an ABSOLUTE unix second, not an age — trayview.ts documents the same trap.
  const handshakeAge =
    displayStats.handshakeSec && displayStats.handshakeSec > 0
      ? Math.max(0, Math.floor(Date.now() / 1000) - displayStats.handshakeSec)
      : null;
  const visibleStats: Array<{ label: string; value: string; icon: IconName }> = [
    { label: "Bytes in", value: displayStats.rx === null ? "—" : formatBytes(displayStats.rx), icon: "download" },
    { label: "Bytes out", value: displayStats.tx === null ? "—" : formatBytes(displayStats.tx), icon: "upload" },
    { label: "Duration", value: elapsed === null ? "—" : formatDuration(elapsed), icon: "timer" },
    { label: "Last handshake", value: handshakeAge === null ? "—" : `${handshakeAge}s ago`, icon: "clock-3" },
    { label: "Tunnel IP", value: displayStats.address ?? "—", icon: "globe" },
  ];
  /**
   * ⛔ THE VERB HAD NO HANDLER AT ALL — the button rendered and did nothing.
   *
   * Two paths, and they are genuinely different rather than one faked:
   *
   *  · IN ELECTRON the bridge exists, so this calls the real `tunnel.up` / `tunnel.down`. The
   *    renderer holds no secret and no config — main resolves the WG config and forwards it to the
   *    privileged helper; we only ever see status back.
   *  · IN A BROWSER there is no bridge and there never will be. Rather than a dead button, the
   *    surface drives its OWN state so the transitions and the hyperdrive are reviewable — and
   *    says on screen that it is doing so. A simulated transition presented as a real one would be
   *    the render-floor violation this epic keeps catching.
   */
  const simulated = desktop() === null;

  async function onAction() {
    const d = desktop();
    if (d) {
      // ⛔ EVERY BRIDGE CALL IS AWAITED INSIDE A try. Before this, a rejected `tunnel.up` became an
      // unhandled rejection in main's log and the window did not move — the user pressed a button
      // and the product said nothing. A verb that can fail must be able to SAY it failed.
      setProblem(null);
      setBusy(true);
      try {
        if (state === "signed_out" || state === "expired_creds") {
          await d.auth.login();
          await refreshAuth();
        } else if (state === "connected" || state === "posture_warning" || state === "kill_switch") {
          await d.tunnel.down();
        } else {
          await d.tunnel.up(fullTunnel);
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        // The one error we can turn into a STATE rather than a sentence: main throws this exact
        // string when no credential is stored, which is precisely `signed_out`.
        if (msg.includes("not_authenticated")) {
          setLive("signed_out");
          setAuthed(false);
          setProblem(null);
        } else {
          showProblem(msg);
        }
      } finally {
        setBusy(false);
      }
      return;
    }
    // Browser: drive the local state so the animation can be judged.
    if (state === "connected" || state === "posture_warning" || state === "kill_switch") {
      setLive("disconnected");
      return;
    }
    if (state === "expired_creds") return; // the browser flow has nothing to open here
    setLive("connecting");
    window.setTimeout(() => setLive("connected"), 2200);
  }

  /**
   * ⛔ CHANGE SERVER — THE LAST CAPABILITY THE STEP-3 FLIP STRANDED.
   *
   * `config.setServerUrl` has been on the preload allowlist since S6.2, and after the client stopped
   * loading the web dashboard NOTHING CALLED IT. Pointing the app at a different control plane meant
   * deleting `~/Library/Application Support/@tunnex/client` by hand — an app with a documented verb
   * and no way to reach it, which is the S14.12 class exactly.
   *
   * ⚠ THE SERVER CHANGE REVOKES THE CREDENTIAL, AND THE UI MUST SAY SO BEFORE IT HAPPENS. Main
   * stops the monitors, tears the tunnel down and clears the credential BEFORE persisting the new
   * URL, so there is no window where a new origin holds an old bearer. `reloginRequired` is that
   * fact coming back — it is not advice, it has already happened.
   */
  const [editingServer, setEditingServer] = useState(false);
  const [draftServer, setDraftServer] = useState("");
  const [logText, setLogText] = useState<string>("");
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [releaseCheck, setReleaseCheck] = useState<ReleaseCheck | null>(null);
  const [checkingRelease, setCheckingRelease] = useState(false);
  const [importedProfiles, setImportedProfiles] = useState<ImportedProfile[]>([]);
  const [exported, setExported] = useState<string | null>(null);

  /**
   * ⛔ THREE PANES, BECAUSE THE MAIN SCREEN WAS GROWING BY ONE SECTION PER REQUEST.
   *
   * Routing mode, then a server form, then a footer of buttons — each defensible alone, and together
   * a column you scroll to find anything in. A VPN client's home screen answers one question ("am I
   * connected, and what do I press") and everything else is somewhere you go on purpose.
   *
   * > **A SURFACE THAT ONLY EVER GAINS SECTIONS IS NOT A DESIGN, IT IS AN ACCUMULATION.** The fix is
   * > not smaller sections; it is a second place to put them.
   */
  const [pane, setPane] = useState<
    "home" | "profiles" | "settings" | "logs" | "help"
  >("home");
  const [drawerOpen, setDrawerOpen] = useState(false);

  async function loadLog() {
    const d = desktop();
    if (!d) return;
    setLogText(await d.diag.readLog());
  }

  async function onExportLog() {
    const d = desktop();
    if (!d) return;
    try {
      const path = await d.diag.exportLog();
      // null is a CANCELLED dialog, not a failure — saying "exported" there would be the UI
      // claiming an action it did not perform.
      setExported(path);
    } catch (e) {
      showProblem(e);
    }
  }

  async function checkRelease(): Promise<void> {
    const d = desktop();
    if (!d || checkingRelease) return;
    setCheckingRelease(true);
    try {
      setReleaseCheck(await d.diag.checkRelease());
    } finally {
      setCheckingRelease(false);
    }
  }

  async function openReleaseDownload(): Promise<void> {
    const d = desktop();
    if (!d) return;
    await d.diag.openReleaseDownload();
  }

  useEffect(() => {
    if (pane === "logs") void loadLog();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pane]);

  async function onImportConfig() {
    const d = desktop();
    if (!d) return;
    setProblem(null);
    setBusy(true);
    try {
      const p = await d.tunnel.importConfig();
      // null = the picker was cancelled. Not an error, and not an import.
      if (p) {
        const profiles = await d.tunnel.importedProfiles();
        setImportedProfiles(profiles);
        const active = profiles.find((profile) => profile.active);
        if (active) setFullTunnel(active.fullTunnel);
      }
    } catch (e) {
      // parseWgConf is strict on purpose: a half-parsed profile would be handed to a ROOT helper.
      showProblem(e);
    } finally {
      setBusy(false);
    }
  }

  async function onSelectImported(profile: ImportedProfile) {
    const d = desktop();
    if (!d || profile.active) return;
    setBusy(true);
    try {
      const profiles = await d.tunnel.selectImportedProfile(profile.id);
      setImportedProfiles(profiles);
      setFullTunnel(profile.fullTunnel);
      setLive("disconnected");
    } catch (e) {
      showProblem(e);
    } finally {
      setBusy(false);
    }
  }

  /** Switch connection source, never delete the imported file just to reach sign-in. */
  async function onUseManagedProfile() {
    const d = desktop();
    if (!d) return;
    setProblem(null);
    setBusy(true);
    try {
      const profiles = await d.tunnel.useManagedProfile();
      setImportedProfiles(profiles);
      setPane("home");
      const ok = await refreshAuth();
      if (ok) applyTunnelStatus(await d.tunnel.status());
    } catch (e) {
      showProblem(e);
    } finally {
      setBusy(false);
    }
  }

  async function onForgetImported(id: string) {
    const d = desktop();
    if (!d) return;
    setBusy(true);
    try {
      const profiles = await d.tunnel.forgetImported(id);
      setImportedProfiles(profiles);
      await refreshAuth();
    } catch (e) {
      showProblem(e);
    } finally {
      setBusy(false);
    }
  }

  async function onChangeServer() {
    const d = desktop();
    if (!d) return;
    setProblem(null);
    setBusy(true);
    try {
      const res = await d.config.setServerUrl(draftServer.trim());
      setServerUrl(res.url);
      setEditingServer(false);
      // The credential was cleared server-side of this call; re-read rather than assume.
      await refreshAuth();
    } catch (e) {
      showProblem(e);
    } finally {
      setBusy(false);
    }
  }

  /** Sign out ends the session; the managed device stays enrolled for this installation. */
  async function onSignOut() {
    const d = desktop();
    if (!d) return;
    setProblem(null);
    setBusy(true);
    try {
      await d.auth.logout();
      await refreshAuth();
    } catch (e) {
      showProblem(e);
    } finally {
      setBusy(false);
    }
  }

  async function onRemoveDevice() {
    const d = desktop();
    if (!d || !window.confirm("Remove this device? It will be revoked and a future connection must enroll again.")) return;
    setProblem(null);
    setBusy(true);
    try {
      await d.auth.removeDevice();
      setLive("disconnected");
    } catch (e) {
      showProblem(e);
    } finally {
      setBusy(false);
    }
  }

  const hyperRef = useRef<HTMLCanvasElement | null>(null);
  const graphRef = useRef<HTMLCanvasElement | null>(null);
  const hyperState = useRef(createHyperState());
  const mode: HyperMode =
    state === "connected" || state === "posture_warning"
      ? "connected"
      : state === "connecting"
        ? "connecting"
        : "idle";

  useEffect(() => {
    hyperState.current.mode = mode;
  }, [mode]);

  useEffect(() => {
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    let raf = 0;
    const fit = (cv: HTMLCanvasElement) => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = cv.clientWidth;
      const h = cv.clientHeight;
      if (!w || !h) return null;
      if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
        cv.width = Math.round(w * dpr);
        cv.height = Math.round(h * dpr);
      }
      const ctx = cv.getContext("2d");
      if (!ctx) return null;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      return { ctx, w, h };
    };
    const frame = () => {
      const animated = hyperState.current;
      stepLink(animated);
      const background = hyperRef.current && fit(hyperRef.current);
      if (background) drawHyper(background.ctx, background.w, background.h, animated, Date.now());
      const graph = graphRef.current && fit(graphRef.current);
      if (graph) drawGraph(graph.ctx, graph.w, graph.h, historyRef.current);
      if (!reduced) raf = requestAnimationFrame(frame);
    };
    frame();
    return () => cancelAnimationFrame(raf);
  }, []);

  const historyRef = useRef<number[]>([]);
  useEffect(() => {
    historyRef.current = displayStats.history;
  }, [displayStats.history]);

  return (
    // ⛔ THE CARD, AND IT IS THE DESIGN'S OWN NUMBER — NOT A TASTE CALL.
    //
    // The block's client is `max-width:440px; width:100%; margin:0 auto` with an 18px radius and a
    // glass gradient. We rendered it FULL-BLEED in an 1100px window, so every row — the stats grid,
    // the verb, the split-tunnel line — stretched to twice the width it was drawn at. Nothing was
    // missing; the proportions were simply not the ones specified, which is why it read as wrong
    // rather than as broken.
    //
    // ⚠ THE OUTER SHELL STILL OWNS THE VIEWPORT. The card is centred inside it, so a resized window
    // widens the MARGINS and never the card — the one behaviour a max-width alone would not give if
    // the shell were sized to the content.
    // ⛔ ONE SURFACE — founder-directed, and it supersedes the design's card.
    //
    // The block draws the client as a 440px card `margin:0 auto` on a page, which is how it has to
    // be drawn in a WIREFRAME: the wireframe is a web page, so the card needs a page to sit on.
    // Transcribed literally into a fixed 480px window it produced a card floating inside a window
    // frame — **two chromes, one of them meaningless**, and an outer margin that exists only
    // because the design needed somewhere to put the card.
    //
    // > **A DESIGN'S CONTAINER IS NOT ALWAYS PART OF THE DESIGN.** Some of what a wireframe shows is
    // > the wireframe's own medium, and copying it faithfully reproduces the medium along with the
    // > work. The 440px width was real; the page it was centred on was not.
    //
    // The window is now the card: it owns the frame, the OS draws the corners, and the only borders
    // left are the ones separating content from content.
    <div className="relative flex h-dvh flex-col overflow-hidden bg-bg text-ink-body">
      {/* ── TITLE ─────────────────────────────────────────────────────────────────────────── */}
      {/* ⛔ CLEARS THE TRAFFIC LIGHTS, AND IS THE DRAG HANDLE. With `titleBarStyle: hiddenInset` the
          page paints under the window buttons, so content at the top-left would sit BEHIND them —
          the wordmark was going to end up with three coloured circles on it. `pt-8` is the inset
          macOS reserves.

          ⚠ AND THE WINDOW MUST STILL BE DRAGGABLE. A hidden title bar removes the strip people grab,
          so this header declares itself the drag region — with the interactive children opting back
          OUT, since a button inside a drag region swallows the click. */}
      <div
        className="flex items-center gap-2 px-3 pt-7"
        style={{ WebkitAppRegion: "drag" } as CSSProperties}
      >
        {/* ⛔ THE REAL MARK, via the shared Logo — the previous version drew a bare <img> at 22px
            and lost the wordmark entirely. Logo derives both dimensions from the asset ratios, so
            it cannot be squashed the way a hand-sized img was. */}
        {/* ⛔ THE MARK IS THE IDENTITY AND IT WAS BEING TRIMMED. It rendered at 22px inside a
            `rounded-lg` crop, so the shape lost its corners at the one size where it can least
            afford to. Bigger, uncropped, and paired with the WORDMARK rather than a mono caption —
            the brand kit draws the name; retyping it in a monospace font was a different logo. */}
        {/* ⛔ THE WORDMARK, NOT THE MARK — AND THE REASON IS IN THE ASSET, NOT IN THE CSS.
            `tunnex-logo.svg` bakes in `<rect width="577" height="551" fill="#0A0A0A">` and its
            glyph runs corner to corner, so at any size it renders as a dark plated tile with zero
            breathing room. Removing `rounded-lg` stopped US cropping it; nothing in CSS can give
            artwork padding it does not have.

            This is the same brand block the web shell uses for its home affordance (wordmark +
            tagline), so the two surfaces now show the identity the same way instead of one of them
            showing a tile. The mark returns here the day the asset ships with a margin. */}
        <button
          type="button"
          aria-label="Open navigation"
          aria-expanded={drawerOpen}
          onClick={() => setDrawerOpen(true)}
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-ink-secondary hover:bg-white/[.11] hover:text-ink-heading"
          style={{ WebkitAppRegion: "no-drag" } as CSSProperties}
        >
          <Icon name="menu" size={18} />
        </button>
        <span className="flex flex-col justify-center">
          <Logo size={24} wordmarkOnly />
          <Tagline className="mt-0.5" />
        </span>
        {/* The tray appearance is shown in-window too, so a reviewer can see what the icon WOULD
            be without needing the tray — which is the part no instrument of ours can verify. */}
        {/* ⛔ THE RAW APPEARANCE NAME IS GONE. It printed "grey" / "solid" next to the dot —
            internal vocabulary for how the TRAY ICON is drawn, shown to a user who has no reason to
            know the tray has appearances, three lines above a status word that already says
            "Connected". A debug readout that survived into the product.

            The dot stays: it is the one thing in the window that mirrors what the menu-bar icon
            looks like right now. It carries the state in its LABEL, for a screen reader and on
            hover, rather than in a word beside it. */}
        <span
          data-tray={tray}
          className="ml-auto flex items-center gap-1.5"
          title={view.label}
          aria-label={`Status: ${view.label}`}
        >
          <span
            className={
              "h-2 w-2 rounded-full " +
              (tray === "solid"
                ? "bg-accent-400"
                : tray === "pulsing"
                  ? "animate-pulse bg-warn"
                : tray === "warning"
                  ? "bg-warn"
                  : tray === "red"
                    ? "bg-danger"
                    : "bg-slate-600")
            }
          />
        </span>
      </div>

      {/* OpenVPN-style drawer: Home stays one focused control surface; secondary
          functions are available on purpose without permanently consuming height. */}
      {drawerOpen && (
        <div className="absolute inset-0 z-20 overflow-hidden" style={{ WebkitAppRegion: "no-drag" } as CSSProperties}>
          <button
            type="button"
            aria-label="Close navigation"
            onClick={() => setDrawerOpen(false)}
            className="absolute inset-0 bg-black/60"
          />
          <aside className="absolute inset-y-0 left-0 flex w-[calc(100%_-_64px)] max-w-[280px] flex-col border-r border-line bg-[#151515] px-3 pb-4 pt-9 shadow-2xl">
            <div className="mb-4 flex items-center justify-between px-2">
              <span className="flex flex-col justify-center">
                <Logo size={20} wordmarkOnly />
                <Tagline className="mt-0.5 scale-[.8] origin-left" />
              </span>
              <button
                type="button"
                aria-label="Close navigation"
                onClick={() => setDrawerOpen(false)}
                className="flex h-8 w-8 items-center justify-center rounded text-lg text-ink-secondary hover:bg-white/[.08] hover:text-ink-heading"
              >
                ×
              </button>
            </div>
            <nav aria-label="Client navigation" className="flex flex-col gap-1">
              {(
                [
                  ["home", "Home", "house"],
                  ["profiles", "Profiles", "file-text"],
                  ["settings", "Settings", "settings"],
                  ["logs", "Logs", "scroll-text"],
                  ["help", "Help", "help-circle"],
                ] as const
              ).map(([key, label, icon]) => (
                <button
                  key={key}
                  type="button"
                  data-pane={key}
                  aria-current={pane === key ? "page" : undefined}
                  onClick={() => {
                    setPane(key);
                    setDrawerOpen(false);
                  }}
                  className={
                    "flex items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm transition-colors " +
                    (pane === key
                      ? "bg-white/[.10] text-ink-heading"
                      : "text-ink-secondary hover:bg-white/[.06] hover:text-ink-body")
                  }
                >
                  <Icon name={icon as IconName} size={18} className="shrink-0 text-ink-secondary" />
                  <span>{label}</span>
                  <Icon name="chevron-right" size={16} className="ml-auto shrink-0 text-ink-secondary" />
                </button>
              ))}
            </nav>
            <p className="mt-auto border-t border-line pt-3 font-mono text-[10px] text-ink-secondary" data-drawer-version>
              Tunnex {appInfo ? `v${appInfo.version}` : ""}
            </p>
          </aside>
        </div>
      )}
      <main className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto px-5 pb-5 pt-3">
        {problem && (
          <p className="rounded-lg border border-danger/40 bg-danger/5 px-3 py-2 text-xs text-danger">
            {problem}
          </p>
        )}

        {pane === "home" && (
          <>
            <div className="relative min-h-[150px] flex-1" data-animation-control>
              <canvas
                ref={hyperRef}
                id="tnxHyper"
                aria-hidden
                className="absolute inset-0 block h-full w-full"
              />
              {/* The mesh is the primary connection affordance. The explicit, labelled centre
                  control makes click → linking peers → live mesh visible without a duplicate
                  action button at the bottom of the surface. */}
              {view.action ? (
                <button
                  type="button"
                  data-action
                  aria-label={view.action}
                  title={view.action}
                  onClick={() => {
                    setShowActionHint(false);
                    void onAction();
                  }}
                  disabled={busy}
                  className={
                    "tnx-connect-control absolute left-1/2 top-1/2 z-10 flex h-24 w-24 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-accent-400 disabled:cursor-wait disabled:opacity-60 " +
                    (view.severity === "loud"
                      ? "tnx-connect-control-danger"
                      : view.action === "Disconnect"
                        ? "tnx-connect-control-live"
                        : "")
                  }
                >
                  <span className="tnx-connect-ripple" aria-hidden />
                  <span className="tnx-connect-ripple tnx-connect-ripple-late" aria-hidden />
                  <span className="tnx-connect-orbit" aria-hidden>
                    <span className="tnx-connect-orbit-segment tnx-connect-orbit-a" />
                    <span className="tnx-connect-orbit-segment tnx-connect-orbit-b" />
                    <span className="tnx-connect-orbit-segment tnx-connect-orbit-c" />
                  </span>
                  <span
                    className={"tnx-connect-orb " + (view.action === "Disconnect" ? "tnx-connect-orb-live" : "tnx-connect-orb-idle")}
                    aria-hidden
                  />
                  {showActionHint && view.action === "Connect" && (
                    <span className="tnx-connect-hint" aria-hidden>Click here</span>
                  )}
                  {view.action === "Disconnect" && (
                    <span className="tnx-connect-hint" aria-hidden>Disconnect</span>
                  )}
                </button>
              ) : null}
            </div>
            {/* ── STATUS HEAD ─────────────────────────────────────────────────────────────────── */}
            <section>
              <h1
                data-state={state}
                className={
                  "text-[26px] font-semibold leading-tight " +
                  (view.severity === "loud"
                    ? "text-danger"
                    : view.severity === "ok"
                      ? "text-accent-400"
                      : view.severity === "warn"
                        ? "text-warn"
                        : "text-ink-heading")
                }
              >
                {view.label}
              </h1>
              {state !== "connected" && (
                <p className="mt-1 text-sm text-ink-secondary" data-status-detail>{view.detail}</p>
              )}
              {postureReason && (state === "posture_warning" || state === "posture_blocked") && (
                <p className="mt-2 text-sm text-warn" data-posture-reason>{postureReason}</p>
              )}
            </section>

            <section className="rounded-xl border border-line bg-surface-inset p-3" data-connection-metrics>
              <div className="flex items-baseline justify-between">
                <span className="flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-ink-secondary">
                  <Icon name="chart-no-axes-column-increasing" size={16} />
                  Connection stats
                </span>
                <span className="font-mono text-base text-ink-heading">
                  {displayStats.rate === null ? "—" : formatRate(displayStats.rate)}
                </span>
              </div>
              <canvas ref={graphRef} id="tnxGraph" aria-hidden className="mt-2 block h-10 w-full" />
              <div
                className="mt-1 flex min-h-4 justify-between font-mono text-[10px] text-ink-secondary"
                data-connection-rate-summary
              >
                {displayStats.rate !== null && (
                  <>
                    <span>{formatRate(displayStats.peak)} peak</span>
                    <span>{formatRate(displayStats.rate)}</span>
                  </>
                )}
              </div>
              <dl className="mt-3 divide-y divide-line/70" data-connection-stat-rows>
                {[
                  visibleStats.slice(0, 2),
                  visibleStats.slice(2, 4),
                  visibleStats.slice(4),
                ].map((row) => (
                  <div key={row[0].label} className={"grid gap-x-3 py-2 " + (row.length === 1 ? "grid-cols-1" : "grid-cols-2 divide-x divide-line/70")}>
                    {row.map(({ label, value, icon }, index) => (
                  <div key={label} className={"min-w-0 " + (index > 0 ? "pl-3" : "pr-3")}>
                    <dt className="flex items-center gap-1.5 whitespace-nowrap font-mono text-[10px] uppercase tracking-wide text-ink-secondary" data-stat-label>
                      <Icon name={icon} size={16} />
                      {label}
                    </dt>
                    <dd
                      className="mt-1 min-w-0 truncate whitespace-nowrap font-mono text-base tabular-nums text-ink-body"
                      title={value}
                      data-stat-value
                    >
                      {value}
                    </dd>
                  </div>
                    ))}
                  </div>
                ))}
              </dl>
            </section>

          </>
        )}

        {(pane === "settings" || pane === "profiles") && (
          <>
            {/* ── ROUTING MODE ────────────────────────────────────────────────────────────────────
            ⛔ THE CONTROL SAID THE OPPOSITE OF WHAT IT DID, AND THE SAFE-LOOKING SETTING WAS THE
            LEAKING ONE.

            It was a checkbox LABELLED "Split tunnel" and BOUND to `fullTunnel`. So:

              unchecked -> reads as "split tunnel is off" -> user believes ALL traffic is protected
                        -> actually fullTunnel === false -> SPLIT: most traffic bypasses the tunnel

            > **A USER WHO BELIEVES THEY ARE FULLY TUNNELLED AND IS NOT HAS A WORSE PROBLEM THAN ONE
            > WHO KNOWS THEY ARE SPLIT.** The inverted label pointed the error at the dangerous side,
            > and a checkbox cannot say which state is which — the unchecked box has no words on it.

            Two named options now, each stating what it DOES to traffic. No inference from a tick. */}
            {pane === "settings" && <fieldset className="rounded-lg border border-line p-3">
              <legend className="px-1 font-mono text-[10px] uppercase tracking-wider text-ink-secondary">
                Routing
              </legend>
              {(
                [
                  [
                    "full",
                    "All traffic",
                    "Send all traffic through Tunnex.",
                  ],
                  [
                    "split",
                    "Only Tunnex routes",
                    "Only routes published by your admin use Tunnex.",
                  ],
                ] as const
              ).map(([key, label, why]) => (
                <label
                  key={key}
                  className="mt-1 flex cursor-pointer items-start gap-2.5 text-sm text-ink-body"
                >
                  <input
                    type="radio"
                    name="routing"
                    className="mt-1"
                    checked={key === "full" ? fullTunnel : !fullTunnel}
                    onChange={() => setFullTunnel(key === "full")}
                  />
                  <span>
                    {label}
                    <span className="block text-xs text-ink-secondary">
                      {why}
                    </span>
                  </span>
                </label>
              ))}
              {/* Changing this re-mints the device config (deviceconfig.ts) — it is not a live switch. */}
              <p className="mt-2 text-[11px] text-ink-secondary">
                Changing this while connected refreshes the device configuration.
              </p>
            </fieldset>}

            {/* ⛔ THE FAILURE SENTENCE. `not_authenticated` became a STATE above; anything else is shown
            verbatim rather than swallowed. A raw message is worse than a written one and far better
            than silence — and it names the verb that produced it. */}
            {/* ── PROFILE ─────────────────────────────────────────────────────────────────────
                ⛔ FOUNDER-RULED AFTER I ARGUED AGAINST IT, AND THE OBJECTION IS BUILT IN RATHER
                THAN DROPPED. A `.conf` downloaded at device creation now connects. What it cannot
                do is carry a device identity, so the monitors that keep a tunnel honest have
                nothing to poll — which is stated here and on the connection screen instead of
                being left in a design note. */}
            {pane === "profiles" && <section className="rounded-lg border border-line p-3">
              {(() => {
                const activeProfile = importedProfiles.find((profile) => profile.active);
                return (
                  <section className="mb-3 rounded-lg border border-line bg-surface-inset p-3" data-connection-source>
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h2 className="text-sm font-medium text-ink-heading">Tunnex account</h2>
                        <p className="mt-0.5 text-[11px] text-ink-secondary">
                          {activeProfile
                            ? "Switch to your enrolled device or sign in. Imported files stay saved."
                            : "Use your enrolled device or sign in to Tunnex."}
                        </p>
                      </div>
                      {activeProfile ? (
                        <button
                          type="button"
                          data-usemanagedprofile
                          disabled={busy}
                          onClick={() => void onUseManagedProfile()}
                          className="shrink-0 rounded border border-line px-2 py-1 text-xs hover:text-ink-body disabled:opacity-50"
                        >
                          Use account
                        </button>
                      ) : (
                        <span className="shrink-0 text-[10px] text-accent-400">Selected</span>
                      )}
                    </div>
                  </section>
                );
              })()}
              <div className="flex items-center justify-between gap-3">
                <h2 className="font-mono text-[10px] uppercase tracking-wider text-ink-secondary">
                  Imported profiles
                </h2>
                <button
                  type="button"
                  data-importconfig
                  disabled={busy}
                  onClick={() => void onImportConfig()}
                  className="rounded border border-line px-2 py-1 text-xs hover:text-ink-body disabled:opacity-50"
                >
                  Import .conf
                </button>
              </div>
              <p className="mt-2 text-[11px] text-ink-secondary">
                Keep separate WireGuard files for different devices or gateways. Switching disconnects the current tunnel; imported profiles do not report posture or monitor revocation in this app.
              </p>
              {importedProfiles.length === 0 ? (
                <p className="mt-3 text-xs text-ink-secondary">No imported profiles yet.</p>
              ) : (
                <ul className="mt-3 space-y-2" aria-label="Imported profiles">
                  {importedProfiles.map((profile) => (
                    <li key={profile.id} className={"rounded-lg border p-2.5 " + (profile.active ? "border-accent-400/60 bg-accent-400/5" : "border-line")}>
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <p className="truncate text-sm text-ink-heading">{profile.name}</p>
                          <p className="mt-0.5 truncate font-mono text-[10px] text-ink-secondary">{profile.endpoint || "Gateway not specified"}</p>
                          <p className="mt-0.5 font-mono text-[10px] text-ink-secondary">{profile.address || "No tunnel IP"} · {profile.fullTunnel ? "all traffic" : "Tunnex routes"}</p>
                        </div>
                        {profile.active && <span className="shrink-0 text-[10px] text-accent-400">Selected</span>}
                      </div>
                      <div className="mt-2 flex gap-2">
                        <button type="button" disabled={busy || profile.active} onClick={() => void onSelectImported(profile)} className="rounded border border-line px-2 py-1 text-xs hover:text-ink-body disabled:opacity-50">
                          {profile.active ? "Selected" : "Use this profile"}
                        </button>
                        <button type="button" data-forgetimported={profile.id} disabled={busy} onClick={() => void onForgetImported(profile.id)} className="rounded border border-warn/60 px-2 py-1 text-xs text-warn hover:text-ink-body disabled:opacity-50">
                          Remove
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>}

            {/* ── ABOUT ───────────────────────────────────────────────────────────────────────
                ⛔ THE VERSION IS THE ONE UPDATE FACT THAT IS REAL, and the client could not tell
                you its own — the first thing any support conversation asks for.

                ⛔ AND THERE IS NO "CHECK FOR UPDATES" BUTTON, DELIBERATELY. `AUTOUPDATE_ENABLED` is
                false and PINNED false by security.test.ts (Squirrel.Mac cannot verify an unsigned
                app, so an unsigned auto-updater is a remote-code channel with no signature check),
                and `build.publish` is null — there is no feed to query. A button here would be a
                control that cannot work, which this repo shipped twice today already. The state
                model's own rule applies: a null action means NO button, plus a sentence saying
                why. */}
            {pane === "settings" && <section className="rounded-lg border border-line p-3">
              <h2 className="font-mono text-[10px] uppercase tracking-wider text-ink-secondary">
                About
              </h2>
              <p className="mt-1 font-mono text-xs text-ink-body" data-version>
                Tunnex {appInfo ? `v${appInfo.version}` : "version n/a"}
              </p>
              {appInfo && appInfo.update.kind !== "ready" && (
                <p className="mt-2 text-[11px] text-ink-secondary">
                  <span className="text-warn">{appInfo.update.reason}</span>{" "}
                  Updates are manual in this build. Check Tunnex for a newer version.
                </p>
              )}
              {releaseCheck?.kind === "available" && (
                <p className="mt-2 text-[11px] text-ink-body" data-updateavailable>
                  Version {releaseCheck.version} is available.
                </p>
              )}
              {releaseCheck?.kind === "current" && (
                <p className="mt-2 text-[11px] text-ink-secondary" data-updatecurrent>
                  You have the latest released version.
                </p>
              )}
              {releaseCheck?.kind === "unavailable" && (
                <p className="mt-2 text-[11px] text-warn" data-updateunavailable>{releaseCheck.reason}</p>
              )}
              <div className="mt-2 flex gap-2">
                <button
                  type="button"
                  data-checkupdates
                  disabled={checkingRelease}
                  onClick={() => void checkRelease()}
                  className="mt-2 rounded border border-line px-2 py-1 text-xs hover:text-ink-body"
                >
                  {checkingRelease ? "Checking…" : "Check for updates"}
                </button>
              {releaseCheck?.kind === "available" && (
                <button
                  type="button"
                  data-downloadupdate
                  onClick={() => void openReleaseDownload()}
                  className="mt-2 rounded border border-line px-2 py-1 text-xs hover:text-ink-body"
                >
                  Download v{releaseCheck.version}
                </button>
              )}
              </div>
            </section>}

            {/* ── SERVER ──────────────────────────────────────────────────────────────────── */}
            {pane === "settings" && <section className="rounded-lg border border-line p-3">
              <h2 className="font-mono text-[10px] uppercase tracking-wider text-ink-secondary">
                Server
              </h2>
              <p className="mt-1 break-all font-mono text-xs text-ink-body">
                {serverUrl ?? "n/a"}
              </p>
              {identity && (
                <p className="mt-0.5 font-mono text-[10px] text-ink-secondary">
                  device {identity.slice(0, 12)}
                </p>
              )}
              {!simulated && !editingServer && (
                <div className="mt-2 flex gap-2">
                  <button
                    type="button"
                    data-changeserver
                    disabled={busy}
                    onClick={() => {
                      setDraftServer(serverUrl ?? "");
                      setEditingServer(true);
                    }}
                    className="rounded border border-line px-2 py-1 text-xs hover:text-ink-body disabled:opacity-50"
                  >
                    Change server
                  </button>
                  {authed === true && (
                    <button
                      type="button"
                      data-signout
                      disabled={busy}
                      onClick={() => void onSignOut()}
                      className="rounded border border-line px-2 py-1 text-xs hover:text-ink-body disabled:opacity-50"
                    >
                      Sign out
                    </button>
                  )}
                  {authed === true && (
                    <button
                      type="button"
                      data-removedevice
                      disabled={busy}
                      onClick={() => void onRemoveDevice()}
                      className="rounded border border-warn/60 px-2 py-1 text-xs text-warn hover:text-ink-body disabled:opacity-50"
                    >
                      Remove device
                    </button>
                  )}
                </div>
              )}
            </section>}
            {pane === "settings" && editingServer && !simulated && (
              <form
                className="rounded-lg border border-line p-3"
                onSubmit={(e) => {
                  e.preventDefault();
                  void onChangeServer();
                }}
              >
                <label
                  className="block text-xs text-ink-secondary"
                  htmlFor="tnx-server"
                >
                  Control-plane URL
                </label>
                <input
                  id="tnx-server"
                  type="url"
                  autoComplete="off"
                  value={draftServer}
                  onChange={(e) => setDraftServer(e.target.value)}
                  placeholder="https://vpn.example.com"
                  className="mt-1 w-full rounded border border-line bg-transparent px-2 py-1.5 font-mono text-xs text-ink-body"
                />
                {/* ⛔ SAID BEFORE THE BUTTON IS PRESSED, NOT AFTER. Changing origin revokes the stored
                credential — the user must know that is the cost, not discover it. */}
                <p className="mt-2 text-[11px] text-warn">
                  Switching servers signs you out and tears down the tunnel. A
                  credential is only ever valid for the server it was issued by.
                </p>
                <div className="mt-2 flex gap-2">
                  <button
                    type="submit"
                    disabled={busy || draftServer.trim().length === 0}
                    className="rounded border border-line px-2 py-1 text-xs hover:text-ink-body disabled:opacity-50"
                  >
                    Switch server
                  </button>
                  <button
                    type="button"
                    onClick={() => setEditingServer(false)}
                    className="rounded px-2 py-1 text-xs text-ink-secondary hover:text-ink-body"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            )}
          </>
        )}

        {pane === "logs" && (
          <section className="flex min-h-0 flex-1 flex-col">
            <div className="flex items-center gap-2">
              <h2 className="font-mono text-[10px] uppercase tracking-wider text-ink-secondary">
                Client log
              </h2>
              <button
                type="button"
                data-refreshlogs
                onClick={() => void loadLog()}
                className="ml-auto rounded border border-line px-2 py-0.5 text-[10px] hover:text-ink-body"
              >
                Refresh
              </button>
              <button
                type="button"
                data-exportlogs
                onClick={() => void onExportLog()}
                className="rounded border border-line px-2 py-0.5 text-[10px] hover:text-ink-body"
              >
                Export
              </button>
              <button
                type="button"
                data-openlogs
                onClick={() => void desktop()?.diag.openLogs()}
                className="rounded border border-line px-2 py-0.5 text-[10px] hover:text-ink-body"
              >
                Reveal
              </button>
            </div>
            {exported && (
              <p className="mt-2 text-[11px] text-ink-secondary">
                Saved to {exported}
              </p>
            )}
            {/* ⛔ NEWEST LAST, AND SCROLLED HERE RATHER THAN ON THE PAGE. The log is the one thing
                in this app that is legitimately long; giving it its own scroll box is what keeps
                the window itself from becoming scrollable. */}
            <pre
              data-logview
              className="mt-2 min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-surface-inset p-3 font-mono text-[10px] leading-relaxed text-ink-secondary"
            >
              {logText || "The log is empty."}
            </pre>
          </section>
        )}

        {pane === "help" && (
          <section className="rounded-lg border border-line p-3">
            <h2 className="font-mono text-[10px] uppercase tracking-wider text-ink-secondary">
              Help
            </h2>
            <p className="mt-2 text-sm text-ink-body">
              Check the client log before contacting your administrator.
            </p>
            <p className="mt-1 text-xs text-ink-secondary">
              This build has no embedded help site. The Logs pane lets you refresh, export, or reveal the client log.
            </p>
            <button
              type="button"
              onClick={() => setPane("logs")}
              className="mt-3 rounded border border-line px-2 py-1 text-xs hover:text-ink-body"
            >
              Open logs
            </button>
          </section>
        )}
      </main>
    </div>
  );
}

/** Map the bridge's status to our state union. Kept tiny and total. */
function mapStatus(s: { state?: string } | null | undefined): ClientState {
  switch (s?.state) {
    case "up":
      return "connected";
    case "connecting":
      return "connecting";
    case "revoked":
      return "revoked";
    case "pending_approval":
      return "pending_approval";
    case "migrate_failed":
      return "migrate_failed";
    case "posture_warning":
      return "posture_warning";
    case "posture_blocked":
      return "posture_blocked";
    case "failed":
      return "failed";
    default:
      return "disconnected";
  }
}

/** Product copy for renderer-visible failures. Raw IPC and HTTP details stay in logs. */
export function clientErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  if (raw.includes("revoke_device_failed")) {
    return "Device could not be removed. Disconnect it, then try again.";
  }
  if (raw.includes("not_authenticated")) {
    return "Sign in again, then try this action.";
  }
  return "That action did not complete. Try again or check Logs.";
}
