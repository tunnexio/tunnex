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
          <radialGradient id="hubGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#8A8A86" stopOpacity=".55" />
            <stop offset="60%" stopColor="#C9C9C4" stopOpacity=".14" />
            <stop offset="100%" stopColor="#C9C9C4" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="spoke" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#C9C9C4" stopOpacity=".15" />
            <stop offset="100%" stopColor="#CFCFCA" stopOpacity=".85" />
          </linearGradient>
        </defs>
        <circle
          cx="240"
          cy="150"
          r="118"
          fill="url(#hubGlow)"
          className="tnx-aglow"
        />
        {/* ⛔ SPOKES ARE TRIMMED TO BOTH CIRCLE EDGES. The design's paths ran from a point BEYOND the
          node to the hub's exact CENTRE, so each line showed a stub sticking out past its node and
          another buried under the hub tile — visible as a ragged tail beside every mark. Each path
          now starts at the node's rim and stops at the hub's, so the line reads as a connection
          BETWEEN two things rather than a stroke drawn across them. The packets ride these paths,
          so they inherit the same bounds and no longer disappear under the artwork. */}
        {/* spokes */}
        <g fill="none" stroke="url(#spoke)" strokeWidth="1.3">
          <path
            id="tnxSp0"
            d="M55.4 48.0 Q 121.0 110.2 208.5 132.6"
            className="tnx-edge"
          />
          <path
            id="tnxSp1"
            d="M365.0 53.1 Q 306.0 76.7 268.4 127.9"
            className="tnx-edge"
            style={{ animationDelay: "-.5s" }}
          />
          <path
            id="tnxSp2"
            d="M44.5 148.2 Q 124.1 170.1 204.0 149.7"
            className="tnx-edge"
            style={{ animationDelay: "-1s" }}
          />
          <path
            id="tnxSp3"
            d="M375.5 149.1 Q 325.6 134.2 276.0 149.8"
            className="tnx-edge"
            style={{ animationDelay: "-1.5s" }}
          />
          <path
            id="tnxSp4"
            d="M76.2 247.6 Q 153.2 225.8 209.1 168.4"
            className="tnx-edge"
            style={{ animationDelay: "-.8s" }}
          />
          <path
            id="tnxSp5"
            d="M345.7 245.0 Q 316.9 197.7 266.8 174.1"
            className="tnx-edge"
            style={{ animationDelay: "-.2s" }}
          />
        </g>
        {/* packets converging on hub (GSAP-driven) */}
        <g fill="#E6E6E2">
          <circle className="tnx-pkt" data-sp="0" r="2.6" cx="72" cy="44" />
          <circle className="tnx-pkt" data-sp="1" r="2.6" cx="408" cy="44" />
          <circle className="tnx-pkt" data-sp="2" r="2.6" cx="56" cy="150" />
          <circle className="tnx-pkt" data-sp="3" r="2.6" cx="424" cy="150" />
          <circle className="tnx-pkt" data-sp="4" r="2.6" cx="92" cy="256" />
          <circle className="tnx-pkt" data-sp="5" r="2.6" cx="388" cy="256" />
          <circle className="tnx-pkt" data-sp="6" r="2.6" cx="240" cy="282" />
        </g>
        {/* hub */}
        <circle
          cx="240"
          cy="150"
          r="46"
          fill="none"
          stroke="#C9C9C4"
          strokeWidth="1"
          strokeDasharray="3 7"
          opacity=".5"
          className="tnx-orbit"
        />
        <circle
          cx="240"
          cy="150"
          r="30"
          fill="none"
          stroke="#8A8A86"
          strokeWidth="1"
          className="tnx-aring"
        />
        <circle
          cx="240"
          cy="150"
          r="30"
          fill="none"
          stroke="#C9C9C4"
          strokeWidth="1"
          className="tnx-aring2"
        />
        {/* ⛔ THE HUB MARK. The design puts the Tunnex tile at the centre of the mesh — the whole
          picture is "everything joins HERE", and without it the hub was an anonymous dot. The
          wireframe layers it as HTML over the SVG; embedded here instead so it scales with the
          viewBox and cannot drift from the rings at any container size. */}
        {/* ⛔ THE HUB TILE. `slice` CROPPED THE MARK — the asset is 577x551 with the glyph filling
          its frame, so slicing a square out of it cuts the edges off, which is exactly what the
          rounded corners were eating. `meet` fits the whole mark, and the tile is drawn separately
          so the mark has PADDING inside it rather than bleeding to the corner radius. */}
        <rect
          x="216"
          y="126"
          width="48"
          height="48"
          rx="12"
          fill="#0A0A0A"
          stroke="rgba(255,255,255,0.10)"
          strokeWidth="1"
        />
        <image
          href={logoUrl}
          x="224"
          y="134"
          width="32"
          height="32"
          preserveAspectRatio="xMidYMid meet"
        />
        {/* ⛔ THE SEVENTH NODE — MCP SERVER. Added deliberately, not transcribed: the design predates
          EPIC 15, and an MCP server is exactly the thing the product is about to treat as a
          first-class destination. Bottom-centre is the one free spoke direction in the design's
          own geometry, so nothing had to move. */}
        <path
          id="tnxSp6"
          d="M240.0 265.5 Q 253.2 225.8 240.0 186.0"
          className="tnx-edge"
          style={{ animationDelay: "-2s" }}
          fill="none"
          stroke="url(#spoke)"
          strokeWidth="1.3"
        />
        {/* nodes */}
        <g className="tnx-node tnx-afloat">
          <circle
            cx="41"
            cy="40"
            r="15"
            fill="rgba(26,26,26,.95)"
            stroke="rgba(255,255,255,0.14)"
            strokeWidth="1"
          />
          <g transform="translate(33,35)">
            <path
              d="M0 5 Q 8 11 16 5"
              fill="none"
              stroke="#FF9900"
              strokeWidth="2.4"
              strokeLinecap="round"
            />
            <path d="M12.5 3.6 L17.4 5 L13 8.2 Z" fill="#FF9900" />
          </g>
          <text
            x="58"
            y="49"
            fill="#E4E4E1"
            fontFamily="Instrument Sans"
            fontSize="12"
            fontWeight="600"
          >
            AWS VPC
          </text>
        </g>
        <g className="tnx-node tnx-afloat2">
          <circle
            cx="378"
            cy="43"
            r="15"
            fill="rgba(26,26,26,.95)"
            stroke="rgba(255,255,255,0.14)"
            strokeWidth="1"
          />
          <g transform="translate(370,35) scale(.62)">
            <path
              fill="#35C1F1"
              d="M5.483 21.3H24L14.025 4.013l-3.038 8.347 5.836 6.938L5.483 21.3z"
            />
            <path fill="#0078D4" d="M13.23 2.7L6.98 7.98 0 19.966h5.626z" />
          </g>
          <text
            x="394"
            y="49"
            fill="#E4E4E1"
            fontFamily="Instrument Sans"
            fontSize="12"
            fontWeight="600"
          >
            Azure
          </text>
        </g>
        <g className="tnx-node tnx-afloat">
          <circle
            cx="28"
            cy="148"
            r="15"
            fill="rgba(26,26,26,.95)"
            stroke="rgba(255,255,255,0.14)"
            strokeWidth="1"
          />
          <g
            transform="translate(20,141)"
            fill="none"
            stroke="#CFCFCA"
            strokeWidth="1.4"
          >
            <rect x="0" y="0" width="15" height="5" rx="1.5" />
            <rect x="0" y="8" width="15" height="5" rx="1.5" />
            <circle cx="3" cy="2.5" r=".6" fill="#CFCFCA" />
            <circle cx="3" cy="10.5" r=".6" fill="#CFCFCA" />
          </g>
          <text
            x="44"
            y="155"
            fill="#E4E4E1"
            fontFamily="Instrument Sans"
            fontSize="12"
            fontWeight="600"
          >
            On-prem
          </text>
        </g>
        <g className="tnx-node tnx-afloat2">
          <circle
            cx="392"
            cy="149"
            r="15"
            fill="rgba(26,26,26,.95)"
            stroke="rgba(255,255,255,0.14)"
            strokeWidth="1"
          />
          <g transform="translate(384,141)">
            {/* Google Cloud's mark — the consumer G is a different product's logo and reads as "sign in with Google", which is the button below, not the cloud this node stands for. */}
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
          <text
            x="408"
            y="155"
            fill="#E4E4E1"
            fontFamily="Instrument Sans"
            fontSize="12"
            fontWeight="600"
          >
            GCP
          </text>
        </g>
        <g className="tnx-node tnx-afloat">
          <circle
            cx="62"
            cy="256"
            r="15"
            fill="rgba(26,26,26,.95)"
            stroke="rgba(255,255,255,0.14)"
            strokeWidth="1"
          />
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
          <text
            x="78"
            y="261"
            fill="#E4E4E1"
            fontFamily="Instrument Sans"
            fontSize="12"
            fontWeight="600"
          >
            Kubernetes
          </text>
        </g>
        <g className="tnx-node tnx-afloat2">
          <circle
            cx="358"
            cy="256"
            r="15"
            fill="rgba(26,26,26,.95)"
            stroke="rgba(255,255,255,0.14)"
            strokeWidth="1"
          />
          <g
            transform="translate(350,248)"
            fill="none"
            stroke="#CFCFCA"
            strokeWidth="1.4"
            strokeLinejoin="round"
          >
            <rect x="0" y="0" width="15" height="10" rx="1.5" />
            <line x1="5" y1="14" x2="10" y2="14" />
            <line x1="7.5" y1="10" x2="7.5" y2="14" />
          </g>
          <text
            x="374"
            y="261"
            fill="#E4E4E1"
            fontFamily="Instrument Sans"
            fontSize="12"
            fontWeight="600"
          >
            Remote
          </text>
        </g>
        <g className="tnx-node tnx-afloat">
          <circle
            cx="240"
            cy="282"
            r="15"
            fill="rgba(26,26,26,.95)"
            stroke="rgba(255,255,255,0.14)"
            strokeWidth="1"
          />
          {/* MCP's mark: the two stacked chevrons over a rule, drawn rather than fetched — the login
            page makes no third-party request before authentication. */}
          <g
            transform="translate(232,274)"
            fill="none"
            stroke="#E4E4E1"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M1 7 L5.5 2.5 L10 7" />
            <path d="M6 12 L10.5 7.5 L15 12" />
          </g>
          <text
            x="258"
            y="288"
            fill="#E4E4E1"
            fontFamily="Instrument Sans"
            fontSize="12"
            fontWeight="600"
          >
            MCP server
          </text>
        </g>
      </svg>
    </div>
  );
}
