package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/tunnexio/tunnex/packages/apptransport"
)

func NewGateway(base string, authority Authority) (*apptransport.Broker, http.Handler) {
	broker := apptransport.NewBrowserBroker(func(ctx context.Context, b apptransport.Binding, serial string) (time.Time, error) {
		return authority.Channel(ctx, BindingFromTransport(b), serial)
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version < 0x0304 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || r.Method != "CONNECT" || r.URL.Path != "/app-access/channel" || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Header.Values("X-App-Hostname")) != 1 {
			deny(w)
			return
		}
		host, e := authorityHost(r.Header.Get("X-App-Hostname"), base, authority)
		if e != nil {
			deny(w)
			return
		}
		revision, err := strconv.ParseInt(r.Header.Get("X-App-Revision"), 10, 64)
		version, versionErr := strconv.ParseInt(r.Header.Get("X-App-Authority-Version"), 10, 64)
		b := apptransport.Binding{OrgID: r.Header.Get("X-App-Org-ID"), GatewayID: r.Header.Get("X-App-Gateway-ID"), AppID: r.Header.Get("X-App-ID"), Generation: r.Header.Get("X-App-Generation"), Digest: r.Header.Get("X-App-Digest"), Purpose: r.Header.Get("X-App-Purpose"), Revision: revision, AuthorityVersion: version, Hostname: host}
		// Org/gateway are not present in ordinary binding headers. They must be
		// supplied on CONNECT and are checked by the authenticated authority.
		if b.Purpose != "browser_proxy" || err != nil || versionErr != nil || !BindingFromTransport(b).Valid() || b.ValidateHeaders(r.Header) != nil || len(r.Header.Values("X-App-Org-ID")) != 1 || len(r.Header.Values("X-App-Gateway-ID")) != 1 {
			deny(w)
			return
		}

		broker.Accept(w, r, b, fmt.Sprintf("%x", r.TLS.PeerCertificates[0].SerialNumber))
	})
	return broker, handler
}

func BindingFromTransport(b apptransport.Binding) Binding {
	return Binding{OrgID: b.OrgID, GatewayID: b.GatewayID, AppID: b.AppID, Generation: b.Generation, Digest: b.Digest, Purpose: "browser_proxy", Revision: b.Revision, AuthorityVersion: b.AuthorityVersion, Hostname: b.Hostname}
}
