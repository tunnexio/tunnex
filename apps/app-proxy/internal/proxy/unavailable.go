package proxy

import (
	"fmt"
	"net/http"
)

// Use the same page for unavailable hosts and denied authority. Never include
// private origin configuration, credentials or upstream errors in a response.
func deny(w http.ResponseWriter) {
	denyPage(w, false)
}

func (h *Handler) deny(w http.ResponseWriter) {
	denyPage(w, h.beam)
}

func denyPage(w http.ResponseWriter, beam bool) {
	brand := "TUNNEX APP ACCESS"
	message := "Reopen this application from My Applications. If this continues, contact your administrator."
	if beam {
		brand = "TUNNEX BEAM"
		message = "This shared app is unavailable. Reopen the original Beam link. If this continues, contact its publisher."
	}
	w.Header().Set("Origin-Agent-Cluster", "?1")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Application unavailable · Tunnex</title>
<style>body{margin:0;background:#0d0f12;color:#f4f5f7;font:16px/1.6 system-ui,sans-serif}main{box-sizing:border-box;max-width:38rem;margin:12vh auto;padding:2rem}.brand{color:#a5acb8;font-size:.8rem;letter-spacing:.12em}h1{font-size:2rem;line-height:1.2;margin:1.2rem 0}p{color:#b9bec8}a{display:inline-block;margin-top:1rem;padding:.65rem 1rem;border:1px solid #565d69;border-radius:.5rem;color:#f4f5f7;text-decoration:none}a:focus-visible{outline:3px solid #94bcff;outline-offset:4px}</style></head>
<body><main><div class="brand">%s</div><h1>Application unavailable</h1><p>%s</p><a href="/">Try again</a></main></body></html>`, brand, message)
}
