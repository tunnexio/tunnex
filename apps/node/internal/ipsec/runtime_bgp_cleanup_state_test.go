package ipsec

import "testing"

func TestBGPRouteWithdrawalPreservesCrashUnion(t *testing.T) {
	e, _, _ := bgpRouteWriterFixture(t)
	first, second := routeTupleFixture(e, 1), routeTupleFixture(e, 2)
	pending := RuntimeBGPRoutes{Sequence: 7, Stage: "pending", Owned: []RuntimeBGPRouteTuple{first}, Target: []RuntimeBGPRouteTuple{second}}
	before, after := e, e
	before.BGPRoutes = &pending
	withdrawal := pending
	withdrawal.Withdrawal = true
	after.BGPRoutes = &withdrawal
	if handled, valid := validBGPRouteWithdrawalSuccessor(before, after); !handled || !valid {
		t.Fatal("crash union withdrawal refused")
	}
	for _, change := range []func(*RuntimeBGPRoutes){
		func(s *RuntimeBGPRoutes) { s.Sequence++ },
		func(s *RuntimeBGPRoutes) { s.Owned = []RuntimeBGPRouteTuple{} },
		func(s *RuntimeBGPRoutes) { s.Target = []RuntimeBGPRouteTuple{} },
		func(s *RuntimeBGPRoutes) { s.Stage = "completed" },
	} {
		altered := withdrawal
		change(&altered)
		after.BGPRoutes = &altered
		if _, valid := validBGPRouteWithdrawalSuccessor(before, after); valid {
			t.Fatal("crash union rewrite admitted")
		}
	}
	before.BGPRoutes = &withdrawal
	completed := RuntimeBGPRoutes{Sequence: 7, Stage: "completed", Withdrawal: true, Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
	after.BGPRoutes = &completed
	if _, valid := validBGPRouteWithdrawalSuccessor(before, after); !valid {
		t.Fatal("proved empty withdrawal completion refused")
	}
	for _, change := range []func(*RuntimeBGPRoutes){
		func(s *RuntimeBGPRoutes) { s.Owned = []RuntimeBGPRouteTuple{first} },
		func(s *RuntimeBGPRoutes) { s.Target = []RuntimeBGPRouteTuple{second} },
		func(s *RuntimeBGPRoutes) { s.Sequence++ },
		func(s *RuntimeBGPRoutes) { s.Withdrawal = false },
		func(s *RuntimeBGPRoutes) { s.Owned = nil },
	} {
		altered := completed
		change(&altered)
		after.BGPRoutes = &altered
		if _, valid := validBGPRouteWithdrawalSuccessor(before, after); valid {
			t.Fatal("unproved withdrawal completion admitted")
		}
	}
}

func TestBGPRouteWithdrawalCommittedRestartAndOverflow(t *testing.T) {
	e, _, _ := bgpRouteWriterFixture(t)
	route := routeTupleFixture(e, 1)
	committed := RuntimeBGPRoutes{Sequence: 8, Stage: "completed", Owned: []RuntimeBGPRouteTuple{route}, Target: []RuntimeBGPRouteTuple{route}}
	before, after := e, e
	before.BGPRoutes = &committed
	pending := RuntimeBGPRoutes{Sequence: 9, Stage: "pending", Withdrawal: true, Owned: []RuntimeBGPRouteTuple{route}, Target: []RuntimeBGPRouteTuple{}}
	after.BGPRoutes = &pending
	if _, valid := validBGPRouteWithdrawalSuccessor(before, after); !valid {
		t.Fatal("committed withdrawal refused")
	}
	committed.Sequence = ^uint64(0)
	pending.Sequence = 0
	if _, valid := validBGPRouteWithdrawalSuccessor(before, after); valid {
		t.Fatal("sequence wrap admitted")
	}
	completed := RuntimeBGPRoutes{Sequence: 9, Stage: "completed", Withdrawal: true, Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
	before.BGPRoutes = &completed
	fresh := RuntimeBGPRoutes{Sequence: 10, Stage: "pending", Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{route}}
	after.BGPRoutes = &fresh
	if _, valid := validBGPRouteWithdrawalSuccessor(before, after); !valid {
		t.Fatal("new reconciler transition refused")
	}
	fresh.Sequence = 9
	if _, valid := validBGPRouteWithdrawalSuccessor(before, after); valid {
		t.Fatal("sequence replay admitted")
	}
	after.BGPRoutes = nil
	if _, valid := validBGPRouteWithdrawalSuccessor(before, after); valid {
		t.Fatal("withdrawal duty erased")
	}
}
