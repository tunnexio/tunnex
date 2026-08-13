//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package wfp

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

// Fundamental WireGuard specific WFP objects.
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

func createWfpSession() (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("Tunnex", "Tunnex persistent WFP session")
	if err != nil {
		return 0, wrapErr(err)
	}

	session := wtFwpmSession0{
		displayData: *sessionDisplayData,
		// S6.7 delta: NON-dynamic (dropped cFWPM_SESSION_FLAG_DYNAMIC) so BFE keeps the objects
		// after this engine handle / the process closes — the kill-switch survives process death.
		txnWaitTimeoutInMSec: windows.INFINITE,
	}

	sessionHandle := uintptr(0)

	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}

	return sessionHandle, nil
}

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{}
	// S6.7 delta: FIXED keys (was windows.GenerateGUID() — random per arm, which made a crashed
	// persistent block unfindable). These are the durable anchor CleanStale/--wfp-clean delete by.
	bo.provider = tunnexProviderGUID
	bo.filters = tunnexSublayerGUID

	//
	// Register provider.
	//
	{
		// S6.7: the provider DESCRIPTION carries the recovery command so `netsh wfp show state`
		// self-documents the escape hatch ON a locked-out box (discoverability requirement).
		displayData, err := createWtFwpmDisplayData0("Tunnex", providerRecoveryHint)
		if err != nil {
			return nil, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: bo.provider,
			displayData: *displayData,
		}
		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil {
			// TODO: cleanup entire call chain of these if failure?
			return nil, wrapErr(err)
		}
	}

	//
	// Register filters sublayer.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Tunnex filters", "Tunnex kill-switch filters")
		if err != nil {
			return nil, wrapErr(err)
		}
		sublayer := wtFwpmSublayer0{
			subLayerKey: bo.filters,
			displayData: *displayData,
			providerKey: &bo.provider,
			weight:      ^uint16(0),
		}
		err = fwpmSubLayerAdd0(session, &sublayer, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	return bo, nil
}

func EnableFirewall(luid uint64, doNotRestrict bool, restrictToDNSServers []netip.Addr) error {
	// S6.7 delta: a persistent block from a prior arm/crash would make our fixed-GUID provider
	// Add fail ALREADY_EXISTS — so clean any stale Tunnex objects first (idempotent). This is
	// also what makes a re-arm self-heal after an un-clean prior arm.
	_ = removePersistentObjects()

	session, err := createWfpSession()
	if err != nil {
		return wrapErr(err)
	}

	objectInstaller := func(session uintptr) error {
		baseObjects, err := registerBaseObjects(session)
		if err != nil {
			return wrapErr(err)
		}

		err = permitWireGuardService(session, baseObjects, 15)
		if err != nil {
			return wrapErr(err)
		}

		if !doNotRestrict {
			if len(restrictToDNSServers) > 0 {
				err = blockDNS(restrictToDNSServers, session, baseObjects, 15, 14)
				if err != nil {
					return wrapErr(err)
				}
			}

			err = permitLoopback(session, baseObjects, 13)
			if err != nil {
				return wrapErr(err)
			}

			err = permitTunInterface(session, baseObjects, 12, luid)
			if err != nil {
				return wrapErr(err)
			}

			err = permitDHCPIPv4(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			err = permitDHCPIPv6(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			err = permitNdp(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			/* TODO: actually evaluate if this does anything and if we need this. It's layer 2; our other rules are layer 3.
			 *  In other words, if somebody complains, try enabling it. For now, keep it off.
			err = permitHyperV(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}
			*/

			err = blockAll(session, baseObjects, 0)
			if err != nil {
				return wrapErr(err)
			}
		}

		return nil
	}

	err = runTransaction(session, objectInstaller)
	if err != nil {
		fwpmEngineClose0(session)
		return wrapErr(err)
	}

	// S6.7 delta: CLOSE the session now — the objects are non-dynamic, so they PERSIST in BFE
	// independent of this handle/process (that IS the point). Upstream kept the session open
	// because DYNAMIC objects die when it closes; ours must survive death.
	fwpmEngineClose0(session)
	return nil
}

// DisableFirewall removes the persistent Tunnex WFP block (graceful teardown). Because the block
// no longer auto-dies with the session, it must be explicitly deleted — the SAME enumerate-and-
// delete as CleanStale and the --wfp-clean escape hatch. Idempotent (nothing armed → no-op).
func DisableFirewall() {
	_ = removePersistentObjects()
}
