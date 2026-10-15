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
		if profile.IPsecPath.ConnectionID == "" {
			path = nil
		}
		config := fqdnrpc.ResolverConfig{ID: profile.ContextConfigID, Version: profile.ContextConfigVersion, ProfileID: profile.ProfileID, IPsecPath: path}
		for _, endpoint := range profile.Endpoints {
			config.Endpoints = append(config.Endpoints, fqdnrpc.ResolverEndpoint{Address: endpoint.Address, Port: endpoint.Port, Transport: endpoint.Transport})
		}
		entry := dnsforward.ResolverProfile{Config: config, ZoneSuffixes: profile.ZoneSuffixes, AllowedSources: profile.AllowedSources}
		for _, record := range profile.StaticRecords {
			entry.StaticRecords = append(entry.StaticRecords, dnsforward.StaticRecord{Name: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL})
		}
		if profile.LANListener != nil {
			entry.LANListener = &dnsforward.LANListener{Address: profile.LANListener.Address, Interface: profile.LANListener.Interface, AllowedSources: profile.LANListener.AllowedSources, DefaultUpstreams: profile.LANListener.DefaultUpstreams}
		}
		profiles = append(profiles, entry)
	}
	return profiles
}
