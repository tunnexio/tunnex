package nodes

import (
	"strings"
	"testing"
	"time"
)

func TestSamePoolVIPOwnershipDeliveryRequiresEveryImmutableFieldAndExpiry(t *testing.T) {
	base := PoolVIPOwnershipDeliveryEnvelope{
		Version: 1, OrgID: "019f6400-0000-7000-8000-000000000001", SiteID: "019f6400-0000-7000-8000-000000000002",
		ClusterID: "019f6400-0000-7000-8000-000000000003", PoolID: "019f6400-0000-7000-8000-000000000004",
		ConnectorNodeID: "019f6400-0000-7000-8000-000000000005", TargetNodeID: "019f6400-0000-7000-8000-000000000006",
		OperationID: "019f6400-0000-7000-8000-000000000007", ManifestIdentity: strings.Repeat("a", 64), Role: "serving",
		PromotionGeneration: 1, ManifestRevision: 2, LeaseEpoch: 3, DeliveryPhase: "serve",
		DeliveryID: "019f6400-0000-7000-8000-000000000008", DeliveryNonce: strings.Repeat("b", 64),
	}
	expires := time.Date(2026, 8, 13, 12, 0, 0, 123000000, time.UTC)
	if !samePoolVIPOwnershipDelivery(base, expires, base, expires) {
		t.Fatal("an exact reissue must compare equal")
	}

	for _, mutate := range []func(*PoolVIPOwnershipDeliveryEnvelope){
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.Version++ },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.OrgID = "019f6400-0000-7000-8000-000000000009" },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.SiteID = "019f6400-0000-7000-8000-000000000009" },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.ClusterID = "019f6400-0000-7000-8000-000000000009" },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.PoolID = "019f6400-0000-7000-8000-000000000009" },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.ConnectorNodeID = "019f6400-0000-7000-8000-000000000009" },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.TargetNodeID = "019f6400-0000-7000-8000-000000000009" },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.OperationID = "019f6400-0000-7000-8000-000000000009" },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.ManifestIdentity = strings.Repeat("c", 64) },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.Role = "withdrawal" },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.PromotionGeneration++ },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.ManifestRevision++ },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.LeaseEpoch++ },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.DeliveryPhase = "withdraw" },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.DeliveryID = "019f6400-0000-7000-8000-000000000009" },
		func(v *PoolVIPOwnershipDeliveryEnvelope) { v.DeliveryNonce = strings.Repeat("c", 64) },
	} {
		changed := base
		mutate(&changed)
		if samePoolVIPOwnershipDelivery(base, expires, changed, expires) {
			t.Fatalf("changed immutable envelope field compared equal: %+v", changed)
		}
	}
	if samePoolVIPOwnershipDelivery(base, expires, base, expires.Add(time.Microsecond)) {
		t.Fatal("changed expiry compared equal")
	}
}
