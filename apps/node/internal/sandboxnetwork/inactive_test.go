package sandboxnetwork

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
)

func TestInactiveCleanupCreatedAndExpiredStoppedPlans(t *testing.T) {
	for _, original := range []bool{false, true} {
		t.Run(map[bool]string{false: "preactivation", true: "offline-expired"}[original], func(t *testing.T) {
			p, _ := fixturePlan(t)
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			store := FilesystemManifests{root}
			if original {
				if err = store.Reserve(Manifest{p, NamespaceIdentity{1, 2, 1101}}); err != nil {
					t.Fatal(err)
				}
			}
			driver := newDriver(p)
			controller := Controller{Store: store, Driver: driver}
			if err = controller.RemoveInactive(context.Background(), p, 1101); err != nil {
				t.Fatal(err)
			}
			if err = controller.InspectInactiveRemoved(context.Background(), p, 1101); err != nil {
				t.Fatal(err)
			}
			if driver.creates != 0 || driver.moves != 0 || driver.commands != 0 {
				t.Fatal("inactive cleanup configured a namespace")
			}
			if err = store.Reserve(Manifest{p, NamespaceIdentity{1, 2, 1101}}); !errors.Is(err, ErrOwnership) {
				t.Fatal("retired epoch activated", err)
			}
			foreign := p
			foreign.Binding.RuntimeID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			if err = controller.RemoveInactive(context.Background(), foreign, 1101); !errors.Is(err, ErrOwnership) {
				t.Fatal("runtime repurposed", err)
			}
			if err = controller.RemoveInactive(context.Background(), p, 1102); !errors.Is(err, ErrOwnership) {
				t.Fatal("worker repurposed", err)
			}
		})
	}
}

func TestInactiveCleanupOnlyDeletesExactOwnedBirthResidue(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned", true: "foreign"}[foreign], func(t *testing.T) {
			p, _ := fixturePlan(t)
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			driver := newDriver(p)
			if err = driver.CreateBirthLink(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			if foreign {
				driver.birth.Alias = "foreign"
			}
			controller := Controller{FilesystemManifests{root}, driver}
			err = controller.RemoveInactive(context.Background(), p, 1101)
			if foreign {
				if !errors.Is(err, ErrOwnership) || driver.birth == nil {
					t.Fatal("foreign residue deleted", err)
				}
			} else if err != nil || driver.birth != nil {
				t.Fatal("owned residue remains", err)
			}
		})
	}
}

func TestInactiveCleanupPreservesOriginalForeignManifest(t *testing.T) {
	p, _ := fixturePlan(t)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := FilesystemManifests{root}
	if err = store.Reserve(Manifest{p, NamespaceIdentity{1, 2, 1101}}); err != nil {
		t.Fatal(err)
	}
	foreign := p
	foreign.Binding.SandboxID = uuid.New()
	if err = store.ReserveInactive(foreign, 1101); !errors.Is(err, ErrOwnership) {
		t.Fatal("historical namespace binding changed", err)
	}
	if _, err = root.Lstat(p.Binding.OperationID.String() + ".inactive.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("denied plan got tombstone", err)
	}
}
