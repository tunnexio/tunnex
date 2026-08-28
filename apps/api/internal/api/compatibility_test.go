package api

// These names predate the S21 detail additions. Keep this compile-time guard
// so OpenAPI enum additions cannot silently rename exported Go client symbols.
var (
	_ PolicyRuleFqdnDestinationStatus = ActiveGeneration
	_ PolicyRuleFqdnDestinationStatus = FeatureUnavailable
	_ PolicyRuleFqdnDestinationStatus = GenerationUnavailable
	_ ListAgentsParamsMcp             = Assigned
	_ ListAgentsParamsMcp             = Unassigned
	_ ListAgentsParamsAccess          = Active
	_ ListAgentsParamsAccess          = None
	_ ListAgentsParamsAccess          = Pending
	_ ListAgentsParamsSort            = Name
	_ ListAgentsParamsDir             = Asc
	_ ListAgentsParamsDir             = Desc
)
