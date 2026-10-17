package fqdnresources

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"strings"
)

func applicationPathValues(p *ApplicationIPsecPath) (any, any) {
	if p == nil {
		return nil, nil
	}
	return p.ConnectionID, p.ConfigurationRevision
}
func sameApplicationPath(a, b *ApplicationIPsecPath) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
func validateApplicationPath(ctx context.Context, q resolverConfigQuerier, org uuid.UUID, in Input) error {
	p := in.ApplicationIPsecPath
	if p == nil {
		return nil
	}
	if in.Context == nil {
		return apierr.BadRequest("fqdn_application_path_unavailable", "select the application resolver context")
	}
	var connection, ready bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ipsec_connections c JOIN ipsec_org_settings s ON s.org_id=c.org_id AND s.enabled WHERE c.id=$1 AND c.org_id=$2 AND c.site_id=$3 AND c.gateway_node_id=$4 AND c.provider_profile='aws-bgp-ipv4-v1' AND c.desired_intent='enabled' AND c.deleted_at IS NULL),fqdn_application_ipsec_path_valid($2,$3,$4,$1,$5)`, p.ConnectionID, org, in.Context.SiteID, in.Context.GatewayID, p.ConfigurationRevision).Scan(&connection, &ready)
	if err != nil {
		return err
	}
	if !connection {
		return apierr.BadRequest("fqdn_application_path_unavailable", "select an enabled AWS BGP connection on the resolver gateway")
	}
	if !ready {
		return apierr.Conflict("fqdn_application_gateway_unsupported", "gateway must freshly report desktop FQDN application support")
	}
	config, err := resolverConfig(ctx, q, org, in.Context.SiteID, in.Context.GatewayID)
	if err != nil {
		return err
	}
	longest := -1
	selected := -1
	for i, profile := range config.Profiles {
		for _, suffix := range profile.ZoneSuffixes {
			if in.FQDN == suffix || strings.HasSuffix(in.FQDN, "."+suffix) {
				if len(suffix) > longest {
					longest = len(suffix)
					selected = i
				} else if len(suffix) == longest && selected != i {
					return apierr.BadRequest("fqdn_application_path_unavailable", "ambiguous static resolver profile")
				}
			}
		}
	}
	if selected >= 0 {
		profile := config.Profiles[selected]
		if profile.IPsecPath == nil && len(profile.Endpoints) > 0 {
			for _, record := range profile.StaticRecords {
				if record.Name == in.FQDN && record.Type == "CNAME" {
					return nil
				}
			}
		}
	}
	return apierr.BadRequest("fqdn_application_path_unavailable", "application path requires an exact static CNAME with configured completion upstreams")
}
