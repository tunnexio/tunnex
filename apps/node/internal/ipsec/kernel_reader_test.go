package ipsec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func readerFixture(t *testing.T) *KernelReader {
	t.Helper()
	r, err := NewKernelReader("/usr/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	r.namespace = func() (string, error) { return "net:[1234]", nil }
	r.run = func(ctx context.Context, args ...string) ([]byte, error) { return []byte("[]"), nil }
	return r
}
func TestKernelReaderOnlyReadCommands(t *testing.T) {
	r := readerFixture(t)
	var calls [][]string
	reads := 0
	r.namespace = func() (string, error) { reads++; return "net:[1234]", nil }
	r.run = func(ctx context.Context, args ...string) ([]byte, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing command deadline")
		}
		calls = append(calls, append([]string(nil), args...))
		return []byte("[]"), nil
	}
	got, err := r.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"-j", "-d", "link", "show"}, {"-j", "-d", "-N", "-4", "route", "show", "table", "all"}}
	if !reflect.DeepEqual(calls, want) || reads != 2 || got.Namespace != "net:[1234]" || len(got.Links) != 0 || len(got.Routes) != 0 {
		t.Fatalf("bad inventory/read contract: %+v %+v %d", got, calls, reads)
	}
}
func TestKernelReaderRefusesAmbiguousRead(t *testing.T) {
	for _, scenario := range []string{"namespace failure", "changed namespace", "link failure", "route failure", "invalid links", "invalid routes", "oversize", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			r := readerFixture(t)
			commands := 0
			nsReads := 0
			r.namespace = func() (string, error) {
				nsReads++
				if scenario == "namespace failure" {
					return "", errors.New("private path")
				}
				if scenario == "changed namespace" && nsReads == 2 {
					return "net:[5678]", nil
				}
				return "net:[1234]", nil
			}
			r.run = func(ctx context.Context, args ...string) ([]byte, error) {
				commands++
				if (scenario == "link failure" && commands == 1) || (scenario == "route failure" && commands == 2) {
					return []byte("sensitive command output"), errors.New("sensitive failure")
				}
				if (scenario == "invalid links" && commands == 1) || (scenario == "invalid routes" && commands == 2) {
					return []byte("null"), nil
				}
				if scenario == "oversize" {
					return make([]byte, (1<<20)+1), nil
				}
				return []byte("[]"), nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			got, err := r.Read(ctx)
			if err == nil {
				t.Fatal("accepted ambiguous read")
			}
			if strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "private") {
				t.Fatal("raw error leak")
			}
			if got.Namespace != "" || len(got.Links) != 0 || len(got.Routes) != 0 {
				t.Fatal("partial inventory returned")
			}
			if scenario == "cancelled" && commands != 0 {
				t.Fatal("command ran after cancellation")
			}
		})
	}
}
func TestKernelReaderAbsoluteExecutable(t *testing.T) {
	for _, path := range []string{"", "ip", "./ip"} {
		if _, err := NewKernelReader(path); err == nil {
			t.Fatal("accepted nonabsolute executable")
		}
	}
}
func TestKernelReaderCancellationDuringRead(t *testing.T) {
	r := readerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	r.run = func(context.Context, ...string) ([]byte, error) { cancel(); return []byte("[]"), nil }
	if _, err := r.Read(ctx); err == nil {
		t.Fatal("accepted cancelled read")
	}
}
func TestKernelReaderCommandBoundsAndRedaction(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("S2S_KERNEL_TEST_HELPER", "1")
	for _, mode := range []string{"success", "overflow", "failure", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
				defer cancel()
			}
			out, err := runKernelCommand(ctx, exe, "-test.run=^TestKernelReaderHelperProcess$", "--", mode)
			if mode == "success" {
				if err != nil || string(out) != "[]" {
					t.Fatalf("unexpected success: %q %v", out, err)
				}
				return
			}
			if err == nil || len(out) != 0 || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("unbounded/unsanitized result: %q %v", out, err)
			}
		})
	}
}
func TestKernelReaderHelperProcess(t *testing.T) {
	if os.Getenv("S2S_KERNEL_TEST_HELPER") != "1" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "success":
		fmt.Print("[]")
	case "overflow":
		fmt.Print(strings.Repeat("x", (1<<20)+1))
	case "deadline":
		time.Sleep(time.Minute)
	case "failure":
		fmt.Fprint(os.Stderr, "sensitive stderr")
		fmt.Print("sensitive stdout")
		os.Exit(7)
	default:
		os.Exit(9)
	}
	os.Exit(0)
}
