// Runner enrollment. Online bootstrap keeps all private identity on the machine.
package main

import (
	"flag"
	"fmt"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxproduct"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"os"
	"path/filepath"
	"time"
)

func main() {
	// TODO(sandbox-reentry): docs/S-sandbox-shelved-main-reentry.md.
	if sandboxproduct.Shelved {
		fmt.Fprintln(os.Stderr, sandboxproduct.Message)
		os.Exit(1)
	}
	destination := flag.String("output", "", "new private output directory")
	dns := flag.String("controller-dns", "", "controller certificate DNS name")
	controller := flag.String("controller-uri", "", "exact controller URI identity")
	runner := flag.String("runner-uri", "", "exact runner URI identity")
	server := flag.String("server", "", "HTTPS API origin for machine bootstrap")
	enrollment := flag.String("enrollment", "", "scoped enrollment UUID; bootstrap token is read only from stdin")
	report := flag.String("qualification-report", "", "bounded actual native qualification report; never grants readiness")
	installConfig := flag.String("install-config", "", "private pinned installer configuration for report transport")
	trial := flag.String("qualification-trial", "", "exact public qualification trial UUID")
	witness := flag.String("trial-witness", "", "bounded actual offline witness file; omit to read authenticated trial status")
	verifyIssued := flag.Bool("verify-issued", false, "verify original local issued identity for an exact installation retry without redeeming a new token")
	flag.Parse()
	if flag.NArg() != 0 || !filepath.IsAbs(*destination) || filepath.Clean(*destination) != *destination {
		fail()
	}
	if *trial != "" || *witness != "" {
		if *report != "" || *server != "" || *enrollment != "" || *dns != "" || *controller != "" || *runner != "" || trialExchange(*trial, *witness, *installConfig, *destination, os.Stdout) != nil {
			fmt.Fprintln(os.Stderr, "qualification_trial_unavailable: inspect the exact trial and pinned controller; no native proof is implied")
			os.Exit(1)
		}
		return
	}
	if *report != "" || *installConfig != "" {
		if *server != "" || *enrollment != "" || *dns != "" || *controller != "" || *runner != "" || uploadQualification(*report, *installConfig, *destination) != nil {
			fmt.Fprintln(os.Stderr, "qualification_report_unavailable: inspect the actual checks and pinned controller connection; acceptance does not grant readiness")
			os.Exit(1)
		}
		fmt.Println("Qualification metadata accepted. Native proof and administrator review still govern readiness.")
		return
	}
	if *server != "" || *enrollment != "" {
		if *dns != "" || *controller != "" || *runner != "" {
			fail()
		}
		var err error
		if *verifyIssued {
			err = verifyIssuedIdentity(*server, *enrollment, *destination)
		} else {
			err = onlineEnrollment(*server, *enrollment, *destination, os.Stdin)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Println("Machine identity issued locally. Installation and activation require explicit host administrator consent.")
		return
	}
	if *verifyIssued {
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
