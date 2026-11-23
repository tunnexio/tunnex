package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestKubernetesCNIGuardRequiresExactRuntimeIdentityAndExistingStore(t *testing.T) {
	for _, identity := range [][2]string{{"", "gateway-uid"}, {"worker-a", ""}, {" ", "gateway-uid"}} {
		if guard, err := newKubernetesCNIAuthorityGuard(t.TempDir(), identity[0], identity[1]); err == nil || guard != nil {
			t.Fatalf("missing identity admitted: guard=%v err=%v", guard != nil, err)
		}
	}
	missing := filepath.Join(t.TempDir(), "not-created")
	if guard, err := newKubernetesCNIAuthorityGuard(missing, "worker-a", "gateway-uid"); err == nil || guard != nil {
		t.Fatalf("missing store admitted: guard=%v err=%v", guard != nil, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("gateway constructor created or changed host state: %v", err)
	}
}

func TestKubernetesCNIGuardDoesNotCreateAuthorityOrLockOnRefusal(t *testing.T) {
	dir := t.TempDir()
	guard, err := newKubernetesCNIAuthorityGuard(dir, "worker-a", "gateway-uid")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, release, err := guard(ctx)
		if release != nil {
			release()
		}
		if err == nil {
			t.Fatal("empty host store granted CNI authority")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("read-only guard wrote host authority: entries=%v err=%v", entries, err)
	}
}

func TestKubernetesHostFactsSourceRequiresNodeAndExistingStoreAndWritesNothing(t *testing.T) {
	for _, node := range []string{"", " "} {
		if source, err := newKubernetesHostFactsSource(t.TempDir(), node); err == nil || source != nil {
			t.Fatalf("missing node admitted: source=%v err=%v", source != nil, err)
		}
	}
	missing := filepath.Join(t.TempDir(), "not-created")
	if source, err := newKubernetesHostFactsSource(missing, "worker-a"); err == nil || source != nil {
		t.Fatalf("missing store admitted: source=%v err=%v", source != nil, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("host facts source created or changed host state: %v", err)
	}
	// An empty state directory has no facts, and asking creates nothing.
	dir := t.TempDir()
	source, err := newKubernetesHostFactsSource(dir, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source(t.Context()); err == nil {
		t.Fatal("empty host store returned host facts")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("read-only facts source wrote host state: entries=%v err=%v", entries, err)
	}
}
