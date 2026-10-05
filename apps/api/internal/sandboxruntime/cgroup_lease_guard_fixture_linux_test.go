//go:build linux

package sandboxruntime

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
)

// Explicit opt-in synthetic test binary only. Production does not have a
// configurable native constructor, process placement or PID manipulation API.
func TestNativeActorCgroupLeaseGuard(t *testing.T) {
	if os.Getenv("TUNNEX_NATIVE_CGROUP_FIXTURE") != "1" {
		t.Skip("approved native synthetic fixture only")
	}
	control, err := readUnifiedCgroup("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`^/tnxsf([0-9a-f]{12})\.slice/tnxsf([0-9a-f]{12})-guard\.service/control$`).FindStringSubmatch(control)
	if len(match) != 3 || match[1] != match[2] {
		t.Fatal("refused foreign native fixture placement")
	}
	receiptPath := "/run/tunnex-supervisor-fixture-" + match[1] + "/guard/native-guard-result.json"
	if os.Getenv("TUNNEX_NATIVE_CGROUP_RECEIPT") != receiptPath {
		t.Fatal("refused foreign receipt destination")
	}
	g, err := newNativeActorCgroupLeaseGuard(control)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	now := time.Now().UTC()
	lease := sandboxrunner.Lease{SandboxID: uuid.New(), Generation: 1, CreatedAt: now, ExpiresAt: now.Add(5 * time.Second)}
	scope, err := g.Prepare(lease)
	if err != nil {
		t.Fatal(err)
	}
	node, ok := scope.record.node.(*nativeCgroupLeaseNode)
	if !ok {
		t.Fatal("native backend absent")
	}
	if err = node.root.Mkdir("payload", 0700); err != nil {
		t.Fatal(err)
	}
	leaf, err := node.root.OpenRoot("payload")
	if err != nil {
		t.Fatal(err)
	}
	defer leaf.Close()
	fd, err := leaf.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	payload := exec.Command("/usr/bin/sleep", "20")
	payload.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	if err = payload.Start(); err != nil {
		t.Fatal(err)
	}
	defer payload.Process.Kill()
	payloadPID := payload.Process.Pid
	actual, err := readUnifiedCgroup("/proc/" + strconv.Itoa(payloadPID) + "/cgroup")
	if err != nil || actual != node.parent+"/payload" {
		t.Fatal("payload placement not proven", actual, err)
	}
	if err = node.CheckRuntime(node.parent, payloadPID, true); err != nil {
		t.Fatal(err)
	}
	caps := map[string]string{}
	for _, file := range []string{"memory.max", "memory.swap.max", "pids.max", "cpu.max"} {
		caps[file], err = readCgroup(node.root, file)
		if err != nil {
			t.Fatal(err)
		}
	}
	if caps["memory.max"] != "134217728" || caps["memory.swap.max"] != "0" || caps["pids.max"] != "64" || caps["cpu.max"] != "100000 100000" {
		t.Fatal("native caps drift", caps)
	}
	// Simulate the owning actor's stalled command lock. Expiry must continue
	// without the periodic sweeper, provider stop, or this mutex progressing.
	var stalledEffect sync.Mutex
	stalledEffect.Lock()
	defer stalledEffect.Unlock()
	waited := make(chan error, 1)
	go func() { waited <- payload.Wait() }()
	select {
	case <-waited:
	case <-time.After(7 * time.Second):
		t.Fatal("native deadline did not kill blocked-effect payload")
	}
	observed := time.Now().UTC()
	if observed.Before(lease.ExpiresAt) {
		t.Fatal("payload stopped before original expiry")
	}
	frozen, err := readCgroup(node.root, "cgroup.freeze")
	if err != nil || frozen != "1" {
		t.Fatal("expired parent not retained frozen", err)
	}
	var expiredEvents string
	deadline := time.Now().Add(time.Second)
	for {
		expiredEvents, err = readCgroup(node.root, "cgroup.events")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains("\n"+expiredEvents+"\n", "\nfrozen 1\n") && strings.Contains("\n"+expiredEvents+"\n", "\npopulated 0\n") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("freeze request did not converge to empty frozen subtree", expiredEvents)
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-g.Fatal():
		t.Fatal("native fence failure", err)
	default:
	}
	lease.Generation++
	resumed, err := g.Prepare(lease)
	if err != nil || resumed.record != scope.record || !resumed.record.expired.Load() {
		t.Fatal("resume replaced or thawed original scope", err)
	}
	// The kernel permits fatal signals in a frozen cgroup. A concurrent clone
	// can therefore be killed before its marker, rather than remain observable
	// as a frozen task. Accept only these two evidenced non-execution outcomes,
	// never an arbitrary Start error or a signal inferred from error text.
	// https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files
	sliceRoot, err := os.OpenRoot(cgroupMount + path.Dir(g.backend.(*nativeCgroupLeaseBackend).parent))
	if err != nil {
		t.Fatal(err)
	}
	defer sliceRoot.Close()
	oomRoots := map[string]*os.Root{"scope": node.root, "actor": g.backend.(*nativeCgroupLeaseBackend).root, "aggregate": sliceRoot}
	beforeOOM, err := nativeOOMSnapshot(oomRoots)
	if err != nil {
		t.Fatal(err)
	}
	late := exec.Command(os.Args[0], "-test.run=^TestNativeGuardLateHelper$", "-test.timeout=3s")
	marker := "/run/tunnex-supervisor-fixture-" + match[1] + "/guard/late-child-executed"
	late.Env = []string{"TUNNEX_NATIVE_LATE_MARKER=" + marker, "GOMAXPROCS=2"}
	late.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	type lateChildResult struct {
		err           error
		pid           int
		execHandshake bool
	}
	lateDone := make(chan lateChildResult, 1)
	go func() {
		err := late.Start()
		result := lateChildResult{err: err, execHandshake: err == nil}
		if late.Process != nil {
			result.pid = late.Process.Pid
		}
		if err == nil {
			result.err = late.Wait()
		}
		lateDone <- result
	}()
	time.Sleep(150 * time.Millisecond)
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("late child executed through frozen parent", err)
	}
	var completed, membershipObserved bool
	var result lateChildResult
	var latePID int
	var lateCgroup string
	select {
	case result = <-lateDone:
		completed = true
	default:
	}
	if !completed {
		procs, readErr := readCgroup(leaf, "cgroup.procs")
		if readErr != nil {
			t.Fatal(readErr)
		}
		latePIDs := strings.Fields(procs)
		if len(latePIDs) > 1 {
			t.Fatal("unexpected late-child membership", procs)
		}
		if len(latePIDs) == 1 {
			latePID, err = strconv.Atoi(latePIDs[0])
			if err != nil || latePID <= 0 {
				t.Fatal("invalid late-child identity")
			}
			lateCgroup, err = readUnifiedCgroup("/proc/" + latePIDs[0] + "/cgroup")
			if err == nil {
				if lateCgroup != node.parent+"/payload" {
					t.Fatal("late-child actual placement mismatched", lateCgroup)
				}
				membershipObserved = true
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal("late-child actual placement unproven", err)
			}
		}
		if !membershipObserved {
			select {
			case result = <-lateDone:
				completed = true
			case <-time.After(300 * time.Millisecond):
				t.Fatal("late child neither observed frozen nor completed with typed kill")
			}
		}
	}
	lateEvents, err := readCgroup(node.root, "cgroup.events")
	if completed {
		deadline = time.Now().Add(time.Second)
		for err == nil && !strings.Contains("\n"+lateEvents+"\n", "\npopulated 0\n") {
			if time.Now().After(deadline) {
				t.Fatal("killed late child left scope populated", lateEvents)
			}
			time.Sleep(5 * time.Millisecond)
			lateEvents, err = readCgroup(node.root, "cgroup.events")
		}
	}
	if err != nil || !strings.Contains("\n"+lateEvents+"\n", "\nfrozen 1\n") {
		t.Fatal("late child not retained in an actually frozen subtree", lateEvents, err)
	}
	freezeRequest, err := readCgroup(node.root, "cgroup.freeze")
	if err != nil || freezeRequest != "1" {
		t.Fatal("original parent was thawed", err)
	}
	afterOOM, err := nativeOOMSnapshot(oomRoots)
	if err != nil {
		t.Fatal(err)
	}
	noOOM := equalNativeOOM(beforeOOM, afterOOM)
	populated := strings.Contains("\n"+lateEvents+"\n", "\npopulated 1\n")
	outcome, err := nativeLateChildOutcome(completed, typedNativeSIGKILL(result.err), true, true, populated, membershipObserved, noOOM)
	if err != nil {
		t.Fatal(err, result.err, beforeOOM, afterOOM)
	}
	if !completed {
		// Test cleanup only, after live frozen placement has been proved.
		kill, err := ownedWritable(leaf, "cgroup.kill", uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		err = writeCgroup(kill, "1")
		kill.Close()
		if err != nil {
			t.Fatal(err)
		}
		select {
		case result = <-lateDone:
			if !typedNativeSIGKILL(result.err) {
				t.Fatal("unexpected private late-child cleanup result", result.err)
			}
		case <-time.After(time.Second):
			t.Fatal("private late child cleanup incomplete")
		}
	}
	// Go's exec error-pipe EOF alone does not prove userspace exec occurred. A
	// reaped child has no observed /proc membership unless sampled above.
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("late child wrote marker before cleanup", err)
	}
	receipt := map[string]any{"version": 1, "status": "passed", "fixture_nonce": match[1], "actor_control_cgroup": control, "scope_parent": node.parent, "sandbox_id": lease.SandboxID, "original_created_at": lease.CreatedAt, "original_expires_at": lease.ExpiresAt, "observed_payload_exit_at": observed, "deadline_observation_lag_ms": observed.Sub(lease.ExpiresAt).Milliseconds(), "payload_pid": payloadPID, "proved_payload_cgroup": actual, "caps": caps, "blocked_effect_deadline": true, "frozen_parent": "1", "expired_cgroup_events": expiredEvents, "late_child_membership_observed": membershipObserved, "clone_into_cgroup_fd": true, "clone_into_cgroup_target": node.parent + "/payload", "late_child_outcome": outcome, "late_child_typed_sigkill": completed && typedNativeSIGKILL(result.err), "late_child_marker_absent": true, "late_exec_handshake_completed": result.execHandshake, "late_child_no_oom": noOOM, "oom_before": beforeOOM, "oom_after": afterOOM, "late_child_cgroup_events": lateEvents, "same_parent_after_generation": true, "late_child_execution_blocked": true, "provider_network_qualification": false}
	if membershipObserved {
		receipt["late_child_pid"], receipt["proved_late_child_cgroup"] = latePID, lateCgroup
	} else {
		receipt["late_child_pid"], receipt["proved_late_child_cgroup"] = nil, nil
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(receiptPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func typedNativeSIGKILL(err error) bool {
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ProcessState == nil {
		return false
	}
	status, ok := exit.ProcessState.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}
func nativeOOMSnapshot(roots map[string]*os.Root) (map[string]map[string]uint64, error) {
	result := make(map[string]map[string]uint64, len(roots))
	for name, root := range roots {
		raw, err := readCgroup(root, "memory.events")
		if err != nil {
			return nil, err
		}
		values := map[string]uint64{}
		for _, line := range strings.Split(raw, "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return nil, ErrUnavailable
			}
			if fields[0] != "oom" && fields[0] != "oom_kill" && fields[0] != "oom_group_kill" {
				continue
			}
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return nil, err
			}
			values[fields[0]] = value
		}
		if len(values) != 3 {
			return nil, ErrUnavailable
		}
		result[name] = values
	}
	return result, nil
}
func equalNativeOOM(a, b map[string]map[string]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for name, values := range a {
		other, ok := b[name]
		if !ok || len(values) != len(other) {
			return false
		}
		for key, value := range values {
			otherValue, found := other[key]
			if !found || otherValue != value {
				return false
			}
		}
	}
	return true
}

func TestNativeGuardLateHelper(t *testing.T) {
	marker := os.Getenv("TUNNEX_NATIVE_LATE_MARKER")
	if marker == "" {
		t.Skip("private synthetic child only")
	}
	if !regexp.MustCompile(`^/run/tunnex-supervisor-fixture-[0-9a-f]{12}/guard/late-child-executed$`).MatchString(marker) {
		t.Fatal("foreign marker")
	}
	if err := os.WriteFile(marker, []byte("executed"), 0600); err != nil {
		t.Fatal(err)
	}
}
