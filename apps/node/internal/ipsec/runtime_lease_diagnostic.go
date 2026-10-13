package ipsec

import "errors"

func maintenanceLeaseFailureStage(err error) string {
	var classified interface{ IPsecLeaseFailureStage() string }
	if errors.As(err, &classified) {
		category := classified.IPsecLeaseFailureStage()
		switch category {
		case "request", "parse", "transport_deadline", "transport_cancel", "transport_other", "http_400", "http_401", "http_403", "http_404", "http_409", "http_409_ineligible", "http_409_conflict", "http_429", "http_5xx", "http_other":
			return "maintenance_lease_" + category
		}
	}
	return "maintenance_lease"
}
