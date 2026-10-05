// Offline operator enrollment. Does not connect to AWS, CP or any workload.
package main

import (
	"flag"
	"fmt"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"os"
	"path/filepath"
	"time"
)

func main() {
	destination := flag.String("output", "", "new private output directory")
	dns := flag.String("controller-dns", "", "controller certificate DNS name")
	controller := flag.String("controller-uri", "", "exact controller URI identity")
	runner := flag.String("runner-uri", "", "exact runner URI identity")
	flag.Parse()
	if flag.NArg() != 0 || !filepath.IsAbs(*destination) || filepath.Clean(*destination) != *destination {
		fail()
	}
	bundle, e := sandboxrunner.Enroll(*dns, *controller, *runner, time.Now().UTC())
	if e != nil {
		fail()
	}
	if os.Mkdir(*destination, 0700) != nil {
		fail()
	}
	files := map[string][]byte{"controller-ca-key.pem": bundle.ControllerCAKey, "ca.pem": bundle.CA, "controller-cert.pem": bundle.ControllerCertificate, "controller-key.pem": bundle.ControllerKey, "runner-cert.pem": bundle.RunnerCertificate, "runner-key.pem": bundle.RunnerKey}
	for name, raw := range files {
		f, e := os.OpenFile(filepath.Join(*destination, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			fail()
		}
		_, e = f.Write(raw)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			fail()
		}
	}
	fmt.Println("Enrollment files written; certificates expire in 24 hours. No services activated.")
}
func fail() {
	fmt.Fprintln(os.Stderr, "runner enrollment failed; inspect and remove any partial operator output before retry")
	os.Exit(1)
}
