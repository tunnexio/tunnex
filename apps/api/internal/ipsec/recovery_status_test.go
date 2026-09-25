package ipsec

import (
	"encoding/json"
	"testing"
)

func TestRecoveryStatusContract(t *testing.T) {
	one, two := 1, 2
	seq := uint64(1)
	for _, tc := range []struct {
		name  string
		m     RuntimeManifest
		r     RuntimeStatusReport
		valid bool
	}{
		{"legacy", RuntimeManifest{}, RuntimeStatusReport{}, true},
		{"legacy cannot claim active", RuntimeManifest{}, RuntimeStatusReport{ActiveSlot: &one}, false},
		{"recovery requires version", RuntimeManifest{RecoveryVersion: &one}, RuntimeStatusReport{}, false},
		{"known unknown", RuntimeManifest{RecoveryVersion: &one}, RuntimeStatusReport{RecoveryVersion: &one, SelectionSequence: &seq}, true},
		{"known active", RuntimeManifest{RecoveryVersion: &one}, RuntimeStatusReport{RecoveryVersion: &one, SelectionSequence: &seq, ActiveSlot: &two}, true},
		{"future refused", RuntimeManifest{RecoveryVersion: &two}, RuntimeStatusReport{RecoveryVersion: &two, SelectionSequence: &seq}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validRecoveryStatus(tc.m, tc.r) != tc.valid {
				t.Fatal("wrong contract disposition")
			}
		})
	}
}

func TestRecoveryStoredMetadataMustAgree(t *testing.T) {
	one, two := 1, 2
	seq := uint64(3)
	report := RuntimeStatusReport{RecoveryVersion: &one, SelectionSequence: &seq, ActiveSlot: &two}
	stored := recoveryStoredTunnels(report)
	raw, _ := json.Marshal(stored)
	var decoded RuntimeStatusReport
	if !decodeRecoveryStored(raw, &decoded) || decoded.ActiveSlot == nil || *decoded.ActiveSlot != 2 {
		t.Fatal("valid observation lost")
	}
	stored[1].ActiveSlot = &one
	raw, _ = json.Marshal(stored)
	if decodeRecoveryStored(raw, &decoded) {
		t.Fatal("conflicting observation metadata accepted")
	}
}
