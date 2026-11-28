package aiinternal

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	// upstreamPrefix is the control plane's agent-channel route for static keys.
	upstreamPrefix = "/agent/ai-key"
	// messagesPath is the one route that also accepts the x-api-key header (founder decision 5).
	messagesPath = "/anthropic/v1/messages"
	// transcriptionsPath carries audio uploads and has the adapter's larger body cap.
	transcriptionsPath = "/v1/audio/transcriptions"

	maxConcurrent     = 16
	requestDeadline   = 35 * time.Second
	bodyLimit         = 256 << 10
	transcriptionCap  = 8<<20 + 64<<10
	peerHeader        = "X-Tunnex-Peer-IP"
	staticKeyPrefix   = "tnx_sk_"
	staticKeyLength   = 56
	staticKeyAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// routes is the allowlist: the listener path and the one method it accepts. Videos are not proxied.
var routes = map[string]string{
	"/v1/chat/completions":   http.MethodPost,
	"/v1/completions":        http.MethodPost,
	"/v1/embeddings":         http.MethodPost,
	"/v1/audio/speech":       http.MethodPost,
	transcriptionsPath:       http.MethodPost,
	"/v1/images/generations": http.MethodPost,
	"/v1/rerank":             http.MethodPost,
	messagesPath:             http.MethodPost,
	"/v1/models":             http.MethodGet,
}

// validStaticKey checks the shape of a static key: the prefix, 56 characters, base62 after the prefix.
// The control plane checks the checksum and everything else.
func validStaticKey(raw string) bool {
	if len(raw) != staticKeyLength || !strings.HasPrefix(raw, staticKeyPrefix) {
		return false
	}
	for i := len(staticKeyPrefix); i < len(raw); i++ {
		if strings.IndexByte(staticKeyAlphabet, raw[i]) < 0 {
			return false
		}
	}
	return true
}

// credential returns the one credential header to forward, or ok=false. Exactly one credential header
// may be present: `Authorization: Bearer tnx_sk_...` on any route, or `X-Api-Key: tnx_sk_...` on the
// messages route only. Human tokens, workload tokens and any other value are never forwarded.
func credential(h http.Header, path string) (name, value string, ok bool) {
	auth, keys := h.Values("Authorization"), h.Values("X-Api-Key")
	if len(auth)+len(keys) != 1 {
		return "", "", false
	}
	if len(auth) == 1 {
		raw, found := strings.CutPrefix(auth[0], "Bearer ")
		if !found || !validStaticKey(raw) {
			return "", "", false
		}
		return "Authorization", "Bearer " + raw, true
	}
	if path != messagesPath || !validStaticKey(keys[0]) {
		return "", "", false
	}
	return "X-Api-Key", keys[0], true
}

type outbound struct {
	path      string
	peer      netip.Addr
	credName  string
	credValue string
	body      []byte
}

type outboundKey struct{}

// Handler serves the internal endpoint. It must only be served behind the accept filter (listener.go):
// sources is checked again here on the TCP peer, never on a header. The outgoing request carries only
// Content-Type and Accept from the caller, the one credential header and X-Tunnex-Peer-IP, which the
// gateway sets from the TCP peer.
func Handler(control *url.URL, transport http.RoundTripper, sources []netip.Prefix) http.Handler {
	slots := make(chan struct{}, maxConcurrent)
	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := pr.In.Context().Value(outboundKey{}).(outbound)
			pr.SetURL(control)
			pr.Out.Host = control.Host
			pr.Out.URL.Path = upstreamPrefix + out.path
			pr.Out.URL.RawPath = ""
			pr.Out.URL.RawQuery = ""
			header := http.Header{}
			if pr.In.Method == http.MethodPost {
				if ct := pr.In.Header.Get("Content-Type"); ct != "" {
					header.Set("Content-Type", ct)
				}
			}
			if accept := pr.In.Header.Get("Accept"); accept != "" {
				header.Set("Accept", accept)
			}
			header.Set(out.credName, out.credValue)
			header.Set(peerHeader, out.peer.String())
			pr.Out.Header = header
			if out.body == nil {
				pr.Out.Body = nil
				pr.Out.ContentLength = 0
			} else {
				pr.Out.Body = io.NopCloser(bytes.NewReader(out.body))
				pr.Out.ContentLength = int64(len(out.body))
			}
			pr.Out.TransferEncoding = nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			refuse(w, http.StatusBadGateway, "gateway unavailable")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerAddr, err := netip.ParseAddrPort(r.RemoteAddr)
		peer := peerAddr.Addr().Unmap()
		if err != nil || !allows(sources, peer) {
			refuse(w, http.StatusForbidden, "forbidden")
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || strings.Contains(r.RequestURI, "?") || !strings.HasPrefix(r.RequestURI, "/") {
			refuse(w, http.StatusBadRequest, "invalid request")
			return
		}
		method, known := routes[r.URL.Path]
		if !known || r.Method != method {
			refuse(w, http.StatusNotFound, "not found")
			return
		}
		credName, credValue, ok := credential(r.Header, r.URL.Path)
		if !ok {
			refuse(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		limit := int64(bodyLimit)
		if r.URL.Path == transcriptionsPath {
			limit = transcriptionCap
		}
		if method == http.MethodGet && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
			refuse(w, http.StatusBadRequest, "invalid request")
			return
		}
		if r.ContentLength > limit {
			refuse(w, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			refuse(w, http.StatusTooManyRequests, "busy")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestDeadline)
		defer cancel()
		out := outbound{path: r.URL.Path, peer: peer, credName: credName, credValue: credValue}
		if method == http.MethodPost {
			// The whole body is read before anything is sent, so an oversized body never leaves the
			// gateway. The slots bound the memory this holds.
			body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
			if err != nil {
				refuse(w, http.StatusBadRequest, "invalid request")
				return
			}
			if int64(len(body)) > limit {
				refuse(w, http.StatusRequestEntityTooLarge, "request too large")
				return
			}
			out.body = body
		}
		proxy.ServeHTTP(w, r.WithContext(context.WithValue(ctx, outboundKey{}, out)))
	})
}

// refuse answers locally with a fixed short message and no upstream detail.
func refuse(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, message, code)
}
