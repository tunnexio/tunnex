package api

// Keep the generated CLI client's pre-S21 exported enum names source-compatible.
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
