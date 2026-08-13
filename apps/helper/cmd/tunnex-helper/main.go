// Command tunnex-helper is the Tunnex privileged tunnel helper (S6.3). It runs as
// a LaunchDaemon (macOS) / Windows service, listens on an owner-only local socket,
// authenticates each caller against the app's install dir, and serves the typed
// tunnel protocol. Fail-closed is enforced by kernel-resident state the backend
// arranges at Up (pf/WFP), NOT by this process staying alive.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/tunnexio/tunnex/apps/helper"
)

func main() {
	// --version prints the build + caller-auth mode (native|stub) so a stub build
	// is immediately visible (smoke step zero).
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("tunnex-helper %s caller-auth: %s\n", helper.HelperVersion, helper.CallerAuthKind())
		return
	}

	// --wfp-clean (S6.7): the ESCAPE HATCH. Remove the persistent Tunnex WFP kill-switch from an
	// admin prompt, even if the service is dead and networking is blocked. Same code path as the
	// startup self-heal. This is the exact command printed in README-RECOVERY.txt / the event log
	// / the app's failed state.
	if len(os.Args) > 1 && os.Args[1] == "--wfp-clean" {
		if err := wfpClean(); err != nil {
			log.Fatalf("tunnex-helper --wfp-clean: %v", err)
		}
		fmt.Println("tunnex-helper: Tunnex WFP kill-switch removed (or none was present). Networking restored.")
		return
	}

	// Under the Windows SCM the process must speak the service control protocol
	// (svc.Run), not just run as a console program — else `sc start` times out (1053).
	// isWindowsService is false on macOS (LaunchDaemon runs the plain executable) and
	// false when the helper is run from a console, so both fall through to serveHelper.
	if isWindowsService() {
		runService() // service_windows.go — wraps serveHelper in the SCM dispatcher
		return
	}
	if err := serveHelper(nil); err != nil {
		log.Fatalf("tunnex-helper: %v", err)
	}
}

// serveHelper sets up the listener + supervisor + server and serves until stop is
// closed (the Windows service Stop path) or the process is killed (stop == nil, the
// LaunchDaemon / console path). Returns the first fatal error instead of exiting, so
// the service dispatcher can report a clean Stopped state.
func serveHelper(stop <-chan struct{}) error {
	// The install dir(s) (for the interim executable-inside-install-dir caller check)
	// and socket path are provided by the launchd plist / Windows service env.
	// TUNNEX_INSTALL_DIR may list several dirs, os.PathListSeparator-joined (a dev
	// install trusts BOTH /usr/local/tunnex and the Electron binary dir).
	installDir := os.Getenv("TUNNEX_INSTALL_DIR")
	socketPath := os.Getenv("TUNNEX_HELPER_SOCKET")
	if socketPath == "" {
		socketPath = helper.DefaultSocketPath()
	}

	ln, err := helper.NewListener(socketPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	sup := helper.NewSupervisor(helper.NewBackend())

	// Startup self-heal: release any kill-switch stranded by a PRIOR helper that died
	// without a graceful Down (crash / kill -9). Runs BEFORE serving so a restart
	// (launchd KeepAlive / SCM restart) un-strands the host instead of re-serving with
	// the stale block.
	if err := sup.SelfHeal(); err != nil {
		log.Printf("tunnex-helper: startup self-heal: %v", err)
	}
	// F6: sweep any domain-scoped resolver files stranded by a prior process that exited without a
	// graceful sweep (reboot / uninstall-without-relaunch). Owned-marker files only; foreign untouched.
	if err := helper.CleanStaleResolvers(); err != nil {
		log.Printf("tunnex-helper: startup resolver clean-stale: %v", err)
	}
	// Self-uninstall watchdog (macOS packaged install): if the owning /Applications
	// app is trashed, the helper releases its kill-switch + removes itself, so
	// drag-to-Trash is fully clean without a script. No-op on the dev/multi-dir install
	// and off macOS.
	startUninstallWatchdog(installDir, sup)

	// S8.5 Slice 1 — the crash/owner-loss resolver sweep. Wired BEFORE the dead-man goroutine (the
	// happens-before makes the field read race-free); fires OUTSIDE s.mu from the dead-man release path
	// only. On a crash/force-quit (no graceful down), when the dead-man drops the block, this also sweeps
	// the owned /etc/resolver files so a stale resolver can't outlive the dead tunnel. Graceful down is
	// already swept client-side (set_resolvers([])). No-op until S8.5's resolver install path goes live.
	sup.SetOnCrashSweep(func() {
		if err := helper.CleanStaleResolvers(); err != nil {
			log.Printf("tunnex-helper: crash resolver sweep: %v", err)
		}
	})

	// Dead-man loop: bounds the fail-closed model. If the owning app stops
	// heartbeating past DeadManDefault (crashed/wedged), auto-release the block so an
	// unrecovered crash can't strand the host indefinitely.
	go func() {
		// Tick on the SHORTER window (min of the wedge/orphan windows) so the fast
		// orphan release (definitive owner death) is honored with fine granularity, not
		// deferred to a coarse 30s tick (S6.8).
		t := time.NewTicker(sup.TickInterval())
		defer t.Stop()
		for range t.C {
			if sup.CheckDeadMan() {
				log.Printf("tunnex-helper: dead-man fired — kill-switch auto-released (owner gone)")
			}
		}
	}()

	// Service Stop → close the listener so Serve returns and the dispatcher reports
	// Stopped. The kill-switch is NOT torn down here (death = enforcement); the next
	// owner's graceful Down, a restart's self-heal, or the dead-man releases it.
	if stop != nil {
		go func() {
			<-stop
			_ = ln.Close()
		}()
	}

	verify := helper.PathCheckVerifier{InstallDirs: filepath.SplitList(installDir)}
	srv := helper.NewServer(sup, verify, helper.NewPeerResolver())

	log.Printf("tunnex-helper %s: listening on %s (install dirs %q, caller-auth: %s)",
		helper.HelperVersion, socketPath, installDir, helper.CallerAuthKind())
	if err := srv.Serve(ln); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
