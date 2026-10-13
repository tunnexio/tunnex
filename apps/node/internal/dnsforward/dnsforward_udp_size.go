package dnsforward

import "golang.org/x/net/dns/dnsmessage"

// Bound downstream UDP independently of an upstream TCP retry. A larger answer
// is available through this gateway's TCP listener instead of relying on IP
// fragmentation across the client tunnel. Without EDNS the DNS limit is 512.
func downstreamUDPResponse(query, response []byte) []byte {
	limit := 512
	var request dnsmessage.Message
	if request.Unpack(query) == nil {
		options := 0
		for _, resource := range request.Additionals {
			if resource.Header.Type == dnsmessage.TypeOPT {
				options++
				limit = int(resource.Header.Class)
				if limit < 512 {
					limit = 512
				}
				if limit > 1232 {
					limit = 1232
				}
			}
		}
		if options > 1 {
			limit = 512
		}
	}
	if len(response) <= limit {
		return response
	}
	var answer dnsmessage.Message
	if answer.Unpack(response) != nil {
		return nil
	}
	answer.Truncated = true
	answer.Answers = nil
	answer.Authorities = nil
	answer.Additionals = nil
	truncated, err := answer.Pack()
	if err != nil || len(truncated) > limit {
		return nil
	}
	return truncated
}
