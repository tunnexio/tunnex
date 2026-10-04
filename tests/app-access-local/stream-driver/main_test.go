package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestOutageAvailabilityCannotQualifyRevocation(t *testing.T) {
	for _, trigger := range []string{"gateway_pause", "gateway_stop", "cp_pause", "redis_pause", "proxy_shutdown"} {
		if !outageTrigger(trigger) {
			t.Fatal("known owned outage refused")
		}
	}
	for _, trigger := range []string{"grant_revoke", "user_disable", "proxy_restart", "outage", "grant_revoke_cp_pause"} {
		if outageTrigger(trigger) {
			t.Fatal("authority/recovery trigger relaxed")
		}
	}
	for _, err := range []error{syscall.ECONNREFUSED, syscall.ECONNRESET, io.EOF, &net.DNSError{IsTimeout: true}} {
		if !outageTransportError(err) {
			t.Fatal("bounded availability failure refused")
		}
	}
	if outageTransportError(errors.New("certificate authority invalid")) {
		t.Fatal("TLS trust failure counted as outage")
	}
}

func TestActualWithdrawalConfirmationMarker(t *testing.T) {
	now := time.Now()
	m := marker{Trigger: "disable", Evidence: "owned-proof.json", Started: now.Add(-5500 * time.Millisecond), Completed: now.Add(-100 * time.Millisecond)}
	if !validMarker(m, now) {
		t.Fatal("five-second confirmed mutation refused")
	}
	m.Completed = now.Add(-1100 * time.Millisecond)
	if validMarker(m, now) {
		t.Fatal("delayed completion marker accepted")
	}
	m.Completed = now
	m.Started = now.Add(-8100 * time.Millisecond)
	if validMarker(m, now) {
		t.Fatal("unbounded mutation accepted")
	}
}

func TestAnnouncedMutationPreservesExactStart(t *testing.T) {
	now := time.Now()
	started := now.Add(-100 * time.Millisecond)
	announcement := marker{Phase: "mutation_started", Started: started}
	if !validAnnouncement(announcement, now.Add(-time.Second), now) {
		t.Fatal("exact recent announcement refused")
	}
	if validAnnouncement(announcement, now, now) {
		t.Fatal("announcement before readiness accepted")
	}
	final := marker{Trigger: "publication-disable", Started: started, Completed: now, Evidence: "actual-event.json"}
	if !validFinalMarker(final, now, started) {
		t.Fatal("matching final marker refused")
	}
	final.Started = final.Started.Add(time.Millisecond)
	if validFinalMarker(final, now, started) {
		t.Fatal("shifted final start accepted")
	}
}

func TestFixedExpiryAllowsConservativeClosureAfterPositiveTraffic(t *testing.T) {
	start := time.Now()
	ready := start.Add(-time.Second)
	early := start.Add(-12 * time.Millisecond)
	bound := start.Add(5 * time.Second)
	if !closureQualified("grant-expiry", true, false, early, ready, start, bound) {
		t.Fatal("conservative expiry closure refused")
	}
	if closureQualified("grant_revoke", true, false, early, ready, start, bound) {
		t.Fatal("pre-revoke closure accepted")
	}
	if closureQualified("grant-expiry", true, false, ready.Add(-time.Millisecond), ready, start, bound) {
		t.Fatal("closure before positive readiness accepted")
	}
	if closureQualified("grant-expiry", true, false, bound.Add(time.Millisecond), ready, start, bound) {
		t.Fatal("late expiry closure accepted")
	}
	if closureQualified("grant-expiry", true, true, early, ready, start, bound) {
		t.Fatal("forced cleanup counted")
	}
}

func TestDriverMaskedFramesAndServerFrameGuards(t *testing.T) {
	var wire bytes.Buffer
	if maskedFrame(&wire, []byte("aa7")) != nil {
		t.Fatal("frame write")
	}
	frame := wire.Bytes()
	if frame[0] != 0x81 || frame[1] != 0x83 || len(frame) != 9 {
		t.Fatal("RFC framing")
	}
	for i, value := range []byte("aa7") {
		if frame[6+i]^frame[2+i%4] != value {
			t.Fatal("mask")
		}
	}
	if readFrame(bytes.NewReader([]byte{0x81, 3, 'a', 'a', '7'})) != nil {
		t.Fatal("unmasked server frame")
	}
	if readFrame(bytes.NewReader([]byte{0x88, 0})) != io.EOF {
		t.Fatal("close frame")
	}
	for _, invalid := range [][]byte{{0x81, 0x80}, {0xc1, 0}, {0x81, 126}, {0x81, 127}} {
		if readFrame(bytes.NewReader(invalid)) == nil {
			t.Fatal("unsupported frame accepted", binary.BigEndian.Uint16(invalid))
		}
	}
}
