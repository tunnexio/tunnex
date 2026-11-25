// edgeprobe runs the real single-IP edge with a fixed next hop. Built only by
// tests/console-client-ip/walk.sh.
package main

import (
	"log"
	"net"
	"os"

	"github.com/tunnexio/tunnex/packages/apptransport/proxyproto"
	"github.com/tunnexio/tunnex/packages/apptransport/sniedge"
)

func main() {
	token, err := proxyproto.LoadToken(os.Getenv("EDGE_TOKEN_FILE"))
	if err != nil {
		log.Fatal(err)
	}
	inner, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}
	l, err := sniedge.New(inner, sniedge.Config{Own: sniedge.Subdomain("share.test"), Default: os.Getenv("DEFAULT"), DefaultToken: os.Getenv("DEFAULT_TOKEN") == "true", Token: token})
	if err != nil {
		log.Fatal(err)
	}
	for {
		if _, err := l.Accept(); err != nil {
			log.Fatal(err)
		}
	}
}
