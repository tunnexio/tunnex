import { useEffect, useRef } from "react";
import logoUrl from "../assets/tunnex-logo.svg";

/**
 * AuthMesh — the login hero, TRANSCRIBED from the wireframe rather than re-imagined.
 *
 * ⛔ THE FIRST ATTEMPT WAS A THUMBNAIL OF THE DESIGN, NOT THE DESIGN. It drew six plain circles at
 * 300x264 with monospace labels, no provider marks, no animation, and put the hero beside the form
 * instead of behind it. The design's own SVG was sitting in the handoff file the whole time.
 *
 * > **WHEN THE SOURCE SHIPS THE ARTEFACT, TRANSCRIBE IT. Re-deriving a picture from a screenshot
 * > reproduces what you noticed about it, which is never the whole of it.**
 *
 * viewBox 0 0 480 300, hub at (240,150) — the design's coordinates, unscaled. `preserveAspectRatio`
 * does the fitting, so the geometry cannot be stretched by a container the way S14.7's flow graph
 * was when a viewBox met `w-full`.
 *
 * The packet dots are driven in JS along their edges because SMIL is unreliable in the Electron
 * renderer and `offset-path` has no Safari/older-Chromium story; a rAF loop is the portable option
 * and is cancelled on unmount.
 */
export function AuthMesh() {
  const ref = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    const svg = ref.current;
    if (!svg) return;
    // ⛔ RESPECT reduced-motion. The mesh is decorative; a user who asked for stillness gets the
    // static picture, and the CSS animations are suppressed by the media query in index.css.
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;

    const pkts = Array.from(svg.querySelectorAll<SVGCircleElement>(".tnx-pkt"));
    const edges = Array.from(
      svg.querySelectorAll<SVGPathElement | SVGLineElement>(".tnx-edge"),
    );
    if (pkts.length === 0 || edges.length === 0) return;

    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = (now - start) / 1000;
      pkts.forEach((p, i) => {
        const edge = edges[i % edges.length];
        const len = (edge as SVGGeometryElement).getTotalLength?.() ?? 0;
        if (!len) return;
        // Each packet runs its edge on its own phase so they never march in lockstep.
        const u = ((t * 0.24 + i * 0.17) % 1) * len;
        const pt = (edge as SVGGeometryElement).getPointAtLength(u);
        p.setAttribute("cx", String(pt.x));
        p.setAttribute("cy", String(pt.y));
      });
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);

  // ⛔ AN INFERENCE, LABELLED AS ONE. `.tnx-afloat` / `.tnx-afloat2` are DEFINED in the handoff's
  // CSS and applied to NOTHING — dead rules in the source. The names ("auth float", two phases
  // .6s apart) say plainly what they were written for, so the node clusters carry them on
  // alternating phases. Recorded as a decision rather than passed off as transcription: the rest
  // of this file is the designer's markup verbatim, and this line is not.
  return (
    <div aria-hidden="true" className="pointer-events-none h-full w-full">
      <svg
        ref={ref}
        id="tnxMesh"
        viewBox="0 0 480 300"
        preserveAspectRatio="xMidYMid meet"
        style={{ width: "100%", height: "100%", overflow: "visible" }}
      >
        <defs>
          {/* Enhanced ambient radial glows */}
          <radialGradient id="hubGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#E11D48" stopOpacity=".35" />
            <stop offset="45%" stopColor="#991B1B" stopOpacity=".15" />
            <stop offset="100%" stopColor="#0F172A" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="hubAura" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#38BDF8" stopOpacity=".20" />
            <stop offset="70%" stopColor="#1E293B" stopOpacity="0" />
          </radialGradient>

          {/* Dual-layer glowing spoke gradient */}
          <linearGradient id="spokeBase" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#334155" stopOpacity=".25" />
            <stop offset="50%" stopColor="#475569" stopOpacity=".45" />
            <stop offset="100%" stopColor="#64748B" stopOpacity=".30" />
          </linearGradient>
          <linearGradient id="spokeStream" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#38BDF8" stopOpacity=".1" />
            <stop offset="50%" stopColor="#F43F5E" stopOpacity=".9" />
            <stop offset="100%" stopColor="#38BDF8" stopOpacity=".2" />
          </linearGradient>

          {/* Glass node gradient */}
          <linearGradient id="nodeCardBg" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgba(30, 41, 59, 0.92)" />
            <stop offset="100%" stopColor="rgba(15, 23, 42, 0.96)" />
          </linearGradient>
        </defs>

        {/* Ambient hub light aura */}
        <circle
          cx="240"
          cy="150"
          r="128"
          fill="url(#hubGlow)"
          className="tnx-aglow"
        />
        <circle
          cx="240"
          cy="150"
          r="80"
          fill="url(#hubAura)"
          className="tnx-aglow"
        />

        {/* ── BASE SPOKES ────────────────────────────────────────────────────────── */}
        <g fill="none" stroke="url(#spokeBase)" strokeWidth="1.2">
          <path id="tnxSp0_base" d="M55.4 48.0 Q 121.0 110.2 208.5 132.6" />
          <path id="tnxSp1_base" d="M365.0 53.1 Q 306.0 76.7 268.4 127.9" />
          <path id="tnxSp2_base" d="M44.5 148.2 Q 124.1 170.1 204.0 149.7" />
          <path id="tnxSp3_base" d="M375.5 149.1 Q 325.6 134.2 276.0 149.8" />
          <path id="tnxSp4_base" d="M76.2 247.6 Q 153.2 225.8 209.1 168.4" />
          <path id="tnxSp5_base" d="M345.7 245.0 Q 316.9 197.7 266.8 174.1" />
          <path id="tnxSp6_base" d="M240.0 265.5 Q 253.2 225.8 240.0 186.0" />
        </g>

        {/* ── FLOWING TUNNEL ENCRYPTED DATA STREAMS ────────────────────────────────── */}
        <g fill="none" stroke="url(#spokeStream)" strokeWidth="1.8">
          <path id="tnxSp0" d="M55.4 48.0 Q 121.0 110.2 208.5 132.6" className="tnx-edge tnx-stream-edge" />
          <path id="tnxSp1" d="M365.0 53.1 Q 306.0 76.7 268.4 127.9" className="tnx-edge tnx-stream-edge" style={{ animationDelay: "-.5s" }} />
          <path id="tnxSp2" d="M44.5 148.2 Q 124.1 170.1 204.0 149.7" className="tnx-edge tnx-stream-edge" style={{ animationDelay: "-1s" }} />
          <path id="tnxSp3" d="M375.5 149.1 Q 325.6 134.2 276.0 149.8" className="tnx-edge tnx-stream-edge" style={{ animationDelay: "-1.5s" }} />
          <path id="tnxSp4" d="M76.2 247.6 Q 153.2 225.8 209.1 168.4" className="tnx-edge tnx-stream-edge" style={{ animationDelay: "-.8s" }} />
          <path id="tnxSp5" d="M345.7 245.0 Q 316.9 197.7 266.8 174.1" className="tnx-edge tnx-stream-edge" style={{ animationDelay: "-.2s" }} />
          <path id="tnxSp6" d="M240.0 265.5 Q 253.2 225.8 240.0 186.0" className="tnx-edge tnx-stream-edge" style={{ animationDelay: "-2s" }} />
        </g>

        {/* High-speed packet pulses */}
        <g fill="#F43F5E">
          <circle className="tnx-pkt" data-sp="0" r="2.2" cx="72" cy="44" />
          <circle className="tnx-pkt" data-sp="1" r="2.2" cx="408" cy="44" />
          <circle className="tnx-pkt" data-sp="2" r="2.2" cx="56" cy="150" />
          <circle className="tnx-pkt" data-sp="3" r="2.2" cx="424" cy="150" />
          <circle className="tnx-pkt" data-sp="4" r="2.2" cx="92" cy="256" />
          <circle className="tnx-pkt" data-sp="5" r="2.2" cx="388" cy="256" />
          <circle className="tnx-pkt" data-sp="6" r="2.2" cx="240" cy="282" />
        </g>

        {/* ── ZERO TRUST HUB CORE ─────────────────────────────────────────────────── */}
        {/* Outer radar perimeter */}
        <circle
          cx="240"
          cy="150"
          r="54"
          fill="none"
          stroke="#475569"
          strokeWidth="1"
          strokeDasharray="4 8"
          opacity=".6"
          className="tnx-orbit"
        />
        {/* Pulsing signal rings */}
        <circle
          cx="240"
          cy="150"
          r="32"
          fill="none"
          stroke="#F43F5E"
          strokeWidth="1.5"
          className="tnx-aring"
        />
        <circle
          cx="240"
          cy="150"
          r="32"
          fill="none"
          stroke="#38BDF8"
          strokeWidth="1"
          className="tnx-aring2"
        />

        {/* Hub Tile Card */}
        <rect
          x="214"
          y="124"
          width="52"
          height="52"
          rx="14"
          fill="#0F172A"
          stroke="rgba(244, 63, 94, 0.4)"
          strokeWidth="1.5"
          style={{
            filter: "drop-shadow(0 0 16px rgba(225, 29, 72, 0.35))",
          }}
        />
        <rect
          x="215"
          y="125"
          width="50"
          height="50"
          rx="13"
          fill="none"
          stroke="rgba(255, 255, 255, 0.15)"
          strokeWidth="1"
        />
        <image
          href={logoUrl}
          x="222"
          y="132"
          width="36"
          height="36"
          preserveAspectRatio="xMidYMid meet"
        />

        {/* Active zero-trust status pulse ring around hub */}
        <circle cx="258" cy="130" r="3.5" fill="#10B981" />
        <circle cx="258" cy="130" r="6" fill="none" stroke="#10B981" strokeWidth="1" opacity="0.6" className="tnx-aring" />

        {/* ── STABLE GLASSMORPHIC NODE CARDS ────────────────────────────────────── */}
        {/* Node 1: AWS VPC */}
        <g className="tnx-node tnx-node-pulse">
          <rect
            x="24"
            y="22"
            width="104"
            height="36"
            rx="18"
            fill="url(#nodeCardBg)"
            stroke="rgba(255, 255, 255, 0.12)"
            strokeWidth="1"
          />
          <circle cx="42" cy="40" r="11" fill="rgba(255, 153, 0, 0.12)" />
          <g transform="translate(34,35) scale(0.9)">
            <path
              d="M0 5 Q 8 11 16 5"
              fill="none"
              stroke="#FF9900"
              strokeWidth="2.4"
              strokeLinecap="round"
            />
            <path d="M12.5 3.6 L17.4 5 L13 8.2 Z" fill="#FF9900" />
          </g>
          <circle cx="57" cy="40" r="2" fill="#10B981" />
          <text
            x="64"
            y="44"
            fill="#F8FAFC"
            fontFamily="Inter, var(--font-sans), sans-serif"
            fontSize="11"
            fontWeight="600"
            letterSpacing="0.02em"
          >
            AWS VPC
          </text>
        </g>

        {/* Node 2: Azure */}
        <g className="tnx-node tnx-node-pulse-alt">
          <rect
            x="360"
            y="25"
            width="96"
            height="36"
            rx="18"
            fill="url(#nodeCardBg)"
            stroke="rgba(255, 255, 255, 0.12)"
            strokeWidth="1"
          />
          <circle cx="378" cy="43" r="11" fill="rgba(53, 193, 241, 0.12)" />
          <g transform="translate(370,35) scale(.62)">
            <path
              fill="#35C1F1"
              d="M5.483 21.3H24L14.025 4.013l-3.038 8.347 5.836 6.938L5.483 21.3z"
            />
            <path fill="#0078D4" d="M13.23 2.7L6.98 7.98 0 19.966h5.626z" />
          </g>
          <circle cx="393" cy="43" r="2" fill="#10B981" />
          <text
            x="400"
            y="47"
            fill="#F8FAFC"
            fontFamily="Inter, var(--font-sans), sans-serif"
            fontSize="11"
            fontWeight="600"
            letterSpacing="0.02em"
          >
            Azure
          </text>
        </g>

        {/* Node 3: On-prem */}
        <g className="tnx-node tnx-node-pulse">
          <rect
            x="12"
            y="130"
            width="106"
            height="36"
            rx="18"
            fill="url(#nodeCardBg)"
            stroke="rgba(255, 255, 255, 0.12)"
            strokeWidth="1"
          />
          <circle cx="30" cy="148" r="11" fill="rgba(148, 163, 184, 0.12)" />
          <g
            transform="translate(22,141)"
            fill="none"
            stroke="#CBD5E1"
            strokeWidth="1.4"
          >
            <rect x="0" y="0" width="15" height="5" rx="1.5" />
            <rect x="0" y="8" width="15" height="5" rx="1.5" />
            <circle cx="3" cy="2.5" r=".6" fill="#CBD5E1" />
            <circle cx="3" cy="10.5" r=".6" fill="#CBD5E1" />
          </g>
          <circle cx="45" cy="148" r="2" fill="#10B981" />
          <text
            x="52"
            y="152"
            fill="#F8FAFC"
            fontFamily="Inter, var(--font-sans), sans-serif"
            fontSize="11"
            fontWeight="600"
            letterSpacing="0.02em"
          >
            On-prem
          </text>
        </g>

        {/* Node 4: GCP */}
        <g className="tnx-node tnx-node-pulse-alt">
          <rect
            x="374"
            y="131"
            width="90"
            height="36"
            rx="18"
            fill="url(#nodeCardBg)"
            stroke="rgba(255, 255, 255, 0.12)"
            strokeWidth="1"
          />
          <circle cx="392" cy="149" r="11" fill="rgba(234, 67, 53, 0.12)" />
          <g transform="translate(384,141)">
            <path
              d="M9.7 4.6 L12.4 4.6 L14.9 2.1 L14.8 1.1 A7.6 7.6 0 0 0 2.4 4.8 A0.9 0.9 0 0 1 3 4.7 Z"
              fill="#EA4335"
            />
            <path
              d="M2.4 4.8 A7.6 7.6 0 0 0 4.7 13.1 L7.4 10.4 A4.5 4.5 0 0 1 5.3 6.8 Z"
              fill="#FBBC05"
            />
            <path
              d="M14.8 1.1 A7.6 7.6 0 0 1 14.6 13.2 L11.4 10.5 A4.5 4.5 0 0 0 11.6 3.9 Z"
              fill="#4285F4"
            />
            <path
              d="M4.7 13.1 A7.6 7.6 0 0 0 14.6 13.2 L11.4 10.5 A4.5 4.5 0 0 1 7.4 10.4 Z"
              fill="#34A853"
            />
          </g>
          <circle cx="407" cy="149" r="2" fill="#10B981" />
          <text
            x="414"
            y="153"
            fill="#F8FAFC"
            fontFamily="Inter, var(--font-sans), sans-serif"
            fontSize="11"
            fontWeight="600"
            letterSpacing="0.02em"
          >
            GCP
          </text>
        </g>

        {/* Node 5: Kubernetes */}
        <g className="tnx-node tnx-node-pulse">
          <rect
            x="44"
            y="238"
            width="122"
            height="36"
            rx="18"
            fill="url(#nodeCardBg)"
            stroke="rgba(255, 255, 255, 0.12)"
            strokeWidth="1"
          />
          <circle cx="62" cy="256" r="11" fill="rgba(50, 108, 229, 0.12)" />
          <g transform="translate(54,248)">
            <polygon
              points="8,0 14.9,3.9 14.9,11.1 8,15 1.1,11.1 1.1,3.9"
              fill="none"
              stroke="#326CE5"
              strokeWidth="1.6"
              strokeLinejoin="round"
            />
            <circle
              cx="8"
              cy="7.5"
              r="2.5"
              fill="none"
              stroke="#326CE5"
              strokeWidth="1.3"
            />
            <g stroke="#326CE5" strokeWidth="1.1" strokeLinecap="round">
              <line x1="8" y1="2.6" x2="8" y2="5" />
              <line x1="12.2" y1="5.1" x2="10.1" y2="6.3" />
              <line x1="12.2" y1="9.9" x2="10.1" y2="8.7" />
              <line x1="8" y1="12.4" x2="8" y2="10" />
              <line x1="3.8" y1="9.9" x2="5.9" y2="8.7" />
              <line x1="3.8" y1="5.1" x2="5.9" y2="6.3" />
            </g>
          </g>
          <circle cx="77" cy="256" r="2" fill="#10B981" />
          <text
            x="84"
            y="260"
            fill="#F8FAFC"
            fontFamily="Inter, var(--font-sans), sans-serif"
            fontSize="11"
            fontWeight="600"
            letterSpacing="0.02em"
          >
            Kubernetes
          </text>
        </g>

        {/* Node 6: Remote */}
        <g className="tnx-node tnx-node-pulse-alt">
          <rect
            x="340"
            y="238"
            width="104"
            height="36"
            rx="18"
            fill="url(#nodeCardBg)"
            stroke="rgba(255, 255, 255, 0.12)"
            strokeWidth="1"
          />
          <circle cx="358" cy="256" r="11" fill="rgba(203, 213, 225, 0.12)" />
          <g
            transform="translate(350,248)"
            fill="none"
            stroke="#CBD5E1"
            strokeWidth="1.4"
            strokeLinejoin="round"
          >
            <rect x="0" y="0" width="15" height="10" rx="1.5" />
            <line x1="5" y1="14" x2="10" y2="14" />
            <line x1="7.5" y1="10" x2="7.5" y2="14" />
          </g>
          <circle cx="373" cy="256" r="2" fill="#10B981" />
          <text
            x="380"
            y="260"
            fill="#F8FAFC"
            fontFamily="Inter, var(--font-sans), sans-serif"
            fontSize="11"
            fontWeight="600"
            letterSpacing="0.02em"
          >
            Remote
          </text>
        </g>

        {/* Node 7: MCP Server */}
        <g className="tnx-node tnx-node-pulse">
          <rect
            x="180"
            y="264"
            width="120"
            height="34"
            rx="17"
            fill="url(#nodeCardBg)"
            stroke="rgba(255, 255, 255, 0.12)"
            strokeWidth="1"
          />
          <circle cx="196" cy="281" r="10" fill="rgba(56, 189, 248, 0.12)" />
          <g
            transform="translate(191,275)"
            fill="none"
            stroke="#38BDF8"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M1 7 L5.5 2.5 L10 7" />
            <path d="M6 12 L10.5 7.5 L15 12" />
          </g>
          <circle cx="211" cy="281" r="2" fill="#10B981" />
          <text
            x="218"
            y="285"
            fill="#F8FAFC"
            fontFamily="Inter, var(--font-sans), sans-serif"
            fontSize="11"
            fontWeight="600"
            letterSpacing="0.02em"
          >
            MCP server
          </text>
        </g>
      </svg>
    </div>
  );
}
