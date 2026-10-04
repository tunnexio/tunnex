package api

// Active, None, and Pending preserve the pre-S21 exported enum names used by
// downstream Go clients. oapi-codegen prefixes these parameter enum values
// because other schemas own the same words; aliases keep that generator detail
// from becoming a source-breaking API change.
const (
	Active  ListAgentsParamsAccess = ListAgentsParamsAccessActive
	None    ListAgentsParamsAccess = ListAgentsParamsAccessNone
	Pending ListAgentsParamsAccess = ListAgentsParamsAccessPending
)

// Preserve the exported FQDN enum names when additive App Access schemas
// make oapi-codegen prefix their generated constants.
const (
	FeatureUnavailable    PolicyRuleFqdnDestinationStatus = PolicyRuleFqdnDestinationStatusFeatureUnavailable
	ProjectionUnavailable PolicyRuleFqdnDestinationStatus = PolicyRuleFqdnDestinationStatusProjectionUnavailable
	OptInDisabled         PolicyRuleFqdnDestinationStatus = PolicyRuleFqdnDestinationStatusOptInDisabled
	GenerationUnavailable PolicyRuleFqdnDestinationStatus = PolicyRuleFqdnDestinationStatusGenerationUnavailable
	ActiveGeneration      PolicyRuleFqdnDestinationStatus = PolicyRuleFqdnDestinationStatusActiveGeneration
	GenerationPending     PolicyRuleFqdnDestinationStatus = PolicyRuleFqdnDestinationStatusGenerationPending
	GenerationWithdrawn   PolicyRuleFqdnDestinationStatus = PolicyRuleFqdnDestinationStatusGenerationWithdrawn
	NotApplicable         PolicyRuleFqdnDestinationStatus = PolicyRuleFqdnDestinationStatusNotApplicable
)

// Preserve pre-App Access lifecycle and upgrade enum names whose generated
// prefixes changed when additive schemas introduced overlapping values.
const (
	Aborted      NodeLifecycleClaimState = NodeLifecycleClaimStateAborted
	Acknowledged NodeLifecycleClaimState = NodeLifecycleClaimStateAcknowledged
	Consumed     NodeLifecycleClaimState = NodeLifecycleClaimStateConsumed
	Expired      NodeLifecycleClaimState = NodeLifecycleClaimStateExpired
	Issued       NodeLifecycleClaimState = NodeLifecycleClaimStateIssued

	UpgradeStatusStateApplying  UpgradeStatusState = Applying
	UpgradeStatusStateAvailable UpgradeStatusState = Available
	UpgradeStatusStateFailed    UpgradeStatusState = Failed
	UpgradeStatusStateHealthy   UpgradeStatusState = Healthy
	UpgradeStatusStateRequested UpgradeStatusState = Requested
)
