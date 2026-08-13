//go:build windows

package main

import (
	"log"

	"golang.org/x/sys/windows/svc"
)

// serviceName must match the name used to register the service (sc create tunnex-helper).
const serviceName = "tunnex-helper"

// isWindowsService reports whether the process was started by the Windows SCM (vs a
// console). Under the SCM we must run the service dispatcher; from a console we serve
// directly (dev). Any detection error → treat as console (fail toward the simpler path).
func isWindowsService() bool {
	is, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return is
}

// helperService adapts serveHelper to the SCM control protocol.
type helperService struct{}

func (helperService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	stop := make(chan struct{})
	errc := make(chan error, 1)
	go func() { errc <- serveHelper(stop) }()

	changes <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				close(stop) // → serveHelper closes the listener, Serve returns
				<-errc
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case err := <-errc:
			// Serve exited on its own (listener/serve error): report Stopped with a
			// non-zero exit so the SCM restart policy can bring it back.
			if err != nil {
				log.Printf("tunnex-helper: %v", err)
			}
			changes <- svc.Status{State: svc.Stopped}
			return false, 1
		}
	}
}

// runService hands control to the SCM dispatcher. Blocks until the service stops.
func runService() {
	if err := svc.Run(serviceName, helperService{}); err != nil {
		log.Fatalf("tunnex-helper: service run: %v", err)
	}
}
