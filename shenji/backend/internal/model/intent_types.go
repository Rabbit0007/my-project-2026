package model

// Structured Intent types for Cairn-style exploration
const (
	// Cairn-style graph search intents. These are capability-seeking
	// exploration directions, not vulnerability-type scanners.
	IntentBootstrapGraph      = "bootstrap_graph"
	IntentExploreEntrypoint   = "explore_entrypoint"
	IntentInspectDataflow     = "inspect_dataflow"
	IntentInspectGuard        = "inspect_guard"
	IntentValidateHypothesis  = "validate_hypothesis"
	IntentRunTool             = "run_tool"
	IntentResolveUnknown      = "resolve_unknown"
	IntentCompareBehavior     = "compare_behavior"
	IntentExpandAttackSurface = "expand_attack_surface"
	IntentPromoteCapability   = "promote_capability"

	// Discovery intents
	IntentSurfaceDiscovery   = "surface_discovery"
	IntentFingerprintConfirm = "fingerprint_confirm"
	IntentJSAnalysis         = "js_analysis"

	// Behavior probing intents
	IntentBehaviorProbe       = "behavior_probe"
	IntentAuthProbe           = "auth_probe"
	IntentIDORProbe           = "idor_probe"
	IntentMassAssignmentProbe = "mass_assignment_probe"
	IntentBusinessLogicProbe  = "business_logic_probe"
	IntentPathTraversalProbe  = "path_traversal_probe"
	IntentSQLiProbe           = "sqli_probe"
	IntentSSRFProbe           = "ssrf_probe"
	IntentUploadProbe         = "upload_probe"
	IntentXSSProbe            = "xss_probe"
	IntentSSTIProbe           = "ssti_probe"
	IntentCommandInjProbe     = "command_injection_probe"
	IntentSecretVerify        = "secret_verify"

	// Code audit intents
	IntentCodeProjectIndex     = "code_project_index"
	IntentCodeSliceAnalysis    = "code_slice_analysis"
	IntentDataflowTrace        = "dataflow_trace"
	IntentRouteToSinkTrace     = "route_to_sink_trace"
	IntentEntryToAuthzTrace    = "entry_to_authz_trace"
	IntentObjectOwnerCheck     = "object_owner_check_trace"
	IntentMassAssignTrace      = "mass_assignment_field_trace"
	IntentFilePathControl      = "file_path_control_trace"
	IntentUploadToExec         = "upload_to_execution_trace"
	IntentSecretToAPI          = "secret_to_privileged_api_trace"
	IntentBusinessStateTrace   = "business_state_transition_trace"
	IntentSQLConstructTrace    = "sql_query_construction_trace"
	IntentDeserializationTrace = "deserialization_reachability_trace"
	IntentTemplateRenderTrace  = "template_render_reachability_trace"
	IntentSSRFURLControl       = "ssrf_url_control_trace"

	// Capability expansion
	IntentCapabilityExpand = "capability_expand"
	IntentGoalAttempt      = "goal_attempt"

	// Finalization
	IntentReportFinalize = "report_finalize"
)

// Blackboard node types (extended for Cairn-style graph)
const (
	NodeOrigin           = "origin"
	NodeGoal             = "goal"
	NodeSurfaceFact      = "surface_fact"
	NodeTechnologyFP     = "technology_fingerprint"
	NodeBehaviorFact     = "behavior_fact"
	NodeBusinessFact     = "business_fact"
	NodeCodeFact         = "code_fact"
	NodeSecretFact       = "secret_fact"
	NodeCredentialFact   = "credential_fact"
	NodeHypothesis       = "hypothesis"
	NodeIntent           = "intent"
	NodeNegativeFact     = "negative_fact"
	NodeEvidence         = "evidence"
	NodeCapability       = "capability"
	NodeEnvironmentModel = "environment_model"
	NodeCoverageGoal     = "coverage_goal"
	NodeExpansionGoal    = "expansion_goal"
	NodeEntrypoint       = "entrypoint"
	NodeAttackSurface    = "attack_surface"
	NodeAuthBoundary     = "auth_boundary"
	NodeDataflow         = "dataflow"
	NodeSink             = "sink"
	NodeTestedPath       = "tested_path"
	NodeUnverifiedRisk   = "unverified_risk"
	NodeCoverageItem     = "coverage_item"
	NodeFindingCandidate = "finding_candidate"
	NodeValidatedFinding = "validated_finding"
	NodeSummary          = "summary"
)

const (
	EdgeForms            = "forms"
	EdgeGenerates        = "generates"
	EdgeProduces         = "produces"
	EdgeValidates        = "validates"
	EdgeRefutes          = "refutes"
	EdgeEnables          = "enables"
	EdgeDerivedFrom      = "derived_from"
	EdgeValidatedBy      = "validated_by"
	EdgeExpandsTo        = "expands_to"
	EdgeBlocks           = "blocks"
	EdgeSpawnedIntent    = "spawned_intent"
	EdgeExecutedTool     = "executed_tool"
	EdgeProducedEvidence = "produced_evidence"
	EdgeSupportsFact     = "supports_fact"
)
