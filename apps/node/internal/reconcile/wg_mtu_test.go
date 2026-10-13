package reconcile

import "testing"

func TestWireGuardUnderlayCeilingAndRecovery(t *testing.T) {
	for _, x := range []struct{ request, underlay, want int }{{1420, 1460, 1380}, {1420, 1500, 1420}, {1280, 1460, 1280}, {1420, 1460, 1380}, {1420, 1500, 1420}} {
		got, err := wireGuardMTU(x.request, x.underlay)
		if err != nil || got != x.want {
			t.Fatalf("%+v got%d %v", x, got, err)
		}
		if got+80 > x.underlay {
			t.Fatal("outer envelope exceeds underlay")
		}
	}
	if 1420+60 <= 1460 {
		t.Fatal("observed QE outer geometry missing")
	}
}
