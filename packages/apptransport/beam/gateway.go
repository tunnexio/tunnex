// Package beam supplies a separate Beam transport seam. It does not grant
// publication or reviewer access; callers must supply current Beam authority.
package beam

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/tunnexio/tunnex/packages/apptransport"
)

const Purpose = "beam_proxy"
const ChannelPath = "/beam/channel"

// NewRegistryGateway accepts current immutable assignments from the authority
// callback. Syntax and a verified certificate are prerequisites; only a fresh
// authority lookup may admit or renew the claimed share binding.
func NewRegistryGateway(authorize apptransport.Authorize) (*apptransport.Broker, http.Handler, error) {
	if authorize == nil {
		return nil, nil, errors.New("Beam authority required")
	}
	broker := apptransport.NewBeamBroker(authorize)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || r.Method != http.MethodConnect || r.URL.Path != ChannelPath || r.URL.RawQuery != "" || r.ProtoMajor != 1 || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			http.Error(w, "Beam channel refused", http.StatusForbidden)
			return
		}
		revision, err := strconv.ParseInt(r.Header.Get("X-App-Revision"), 10, 64)
		version, versionErr := strconv.ParseInt(r.Header.Get("X-App-Authority-Version"), 10, 64)
		binding := apptransport.Binding{OrgID: r.Header.Get("X-App-Org-ID"), AppID: r.Header.Get("X-App-ID"), GatewayID: r.Header.Get("X-App-Gateway-ID"), Generation: r.Header.Get("X-App-Generation"), Digest: r.Header.Get("X-App-Digest"), Hostname: r.Header.Get("X-App-Hostname"), Purpose: r.Header.Get("X-App-Purpose"), Revision: revision, AuthorityVersion: version}
		if err != nil || versionErr != nil || !validBinding(binding) || binding.ValidateHeaders(r.Header) != nil {
			http.Error(w, "Beam channel refused", http.StatusForbidden)
			return
		}
		_ = broker.Accept(w, r, binding, r.TLS.PeerCertificates[0].SerialNumber.Text(16))
	})
	return broker, handler, nil
}

// The shared transport's AppID and GatewayID slots carry a Beam share ID and
// connector ID here. The distinct purpose prevents App Access authority reuse.
func validBinding(b apptransport.Binding) bool {
	for _, id := range []string{b.OrgID, b.AppID, b.GatewayID, b.Generation} {
		if len(id) != 36 || id != strings.ToLower(id) || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			return false
		}
		raw, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil || len(raw) != 16 || id == "00000000-0000-0000-0000-000000000000" {
			return false
		}
	}
	digest, err := hex.DecodeString(b.Digest)
	host, hostErr := apptransport.ExactHost(b.Hostname, "")
	return b.Purpose == Purpose && b.Revision > 0 && b.AuthorityVersion > 0 && err == nil && len(digest) == 32 && b.Digest == strings.ToLower(b.Digest) && hostErr == nil && host == b.Hostname
}

// NewGateway serves one immutable assignment for the feasibility slice. A
// production registry and desktop credential bootstrap belong to later stories.
// The callback authenticates the verified certificate serial against current
// actor/org/share/connector/generation authority, including renewal.
func NewGateway(binding apptransport.Binding, authorize apptransport.Authorize) (*apptransport.Broker, http.Handler, error) {
	if !validBinding(binding) || authorize == nil {
		return nil, nil, errors.New("invalid Beam authority binding")
	}
	broker := apptransport.NewBeamBroker(authorize)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || r.Method != http.MethodConnect || r.URL.Path != ChannelPath || r.URL.RawQuery != "" || r.ProtoMajor != 1 || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || binding.ValidateHeaders(r.Header) != nil {
			http.Error(w, "Beam channel refused", http.StatusForbidden)
			return
		}
		serial := r.TLS.PeerCertificates[0].SerialNumber.Text(16)
		_ = broker.Accept(w, r, binding, serial)
	})
	return broker, handler, nil
}
