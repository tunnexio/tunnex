package main

import (
	"github.com/tunnexio/tunnex/apps/node/internal/dnsforward"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func dnsResolverProfilesFrom(policy *nodepolicy.Compiled) []dnsforward.ResolverProfile {
	if policy == nil {
		return nil
	}
	profiles := make([]dnsforward.ResolverProfile, 0, len(policy.DNSResolverProfiles))
	for _, profile := range policy.DNSResolverProfiles {
		path := &fqdnrpc.IPsecPath{ConnectionID: profile.IPsecPath.ConnectionID, ConfigurationRevision: profile.IPsecPath.ConfigurationRevision, SourceAddress: profile.IPsecPath.SourceAddress}
		config := fqdnrpc.ResolverConfig{ID: profile.ContextConfigID, Version: profile.ContextConfigVersion, ProfileID: profile.ProfileID, IPsecPath: path}
		for _, endpoint := range profile.Endpoints {
			config.Endpoints = append(config.Endpoints, fqdnrpc.ResolverEndpoint{Address: endpoint.Address, Port: endpoint.Port, Transport: endpoint.Transport})
		}
		profiles = append(profiles, dnsforward.ResolverProfile{Config: config, ZoneSuffixes: profile.ZoneSuffixes, AllowedSources: profile.AllowedSources})
	}
	return profiles
}
