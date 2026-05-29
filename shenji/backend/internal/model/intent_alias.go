package model

import "strings"

// legacyIntentMap maps legacy vuln-type intent names to their modern clue-driven
// equivalents. The second value is the legacy_hint to preserve in ConstraintsJSON.
var legacyIntentMap = map[string]struct {
	Modern string
	Hint   string
}{
	// Vuln-type intents (original Phase 3 mapping)
	"sql_injection_validation": {IntentClueValidate, "sql_injection"},
	"idor_test":                {IntentClueValidate, "cross_user_object_access"},
	"xss_test":                 {IntentClueValidate, "xss"},
	"ssrf_test":                {IntentClueValidate, "ssrf"},
	"rce_test":                 {IntentClueValidate, "rce"},
	"lfi_test":                 {IntentClueValidate, "lfi"},
	"xxe_test":                 {IntentClueValidate, "xxe"},
	"recon":                    {IntentScopeObservation, "recon"},
	"fingerprint":              {IntentScopeObservation, "fingerprint"},
	"code_trace":               {IntentClueChainExtend, "code_trace"},
	"dataflow_trace":           {IntentClueChainExtend, "dataflow_trace"},
	"inspect_auth_boundary":    {IntentClueChainExtend, "inspect_auth_boundary"},
	"inspect_owner_check":      {IntentClueChainExtend, "inspect_owner_check"},
	"validate_candidate_path":  {IntentClueValidate, "validate_candidate_path"},
	"collect_evidence":         {IntentClueCollect, "collect_evidence"},
	"validate":                 {IntentClueValidate, "validate"},

	// Graph-search intents (Phase 5 expansion — these are produced by the old prompt)
	"bootstrap_graph":      {IntentScopeObservation, "bootstrap_graph"},
	"discover_entrypoints": {IntentScopeObservation, "discover_entrypoints"},
	"enumerate_surfaces":   {IntentScopeObservation, "enumerate_surfaces"},
	"explore_entrypoint":   {IntentClueCollect, "explore_entrypoint"},
	"inspect_dataflow":     {IntentClueChainExtend, "inspect_dataflow"},
	"inspect_guard":        {IntentClueChainExtend, "inspect_guard"},
	"inspect_sink_reachability": {IntentClueChainExtend, "inspect_sink_reachability"},
	"validate_hypothesis":  {IntentClueValidate, "validate_hypothesis"},
	"run_tool":             {IntentClueCollect, "run_tool"},
	"resolve_unknown":      {IntentClueCollect, "resolve_unknown"},
	"compare_behavior":     {IntentClueValidate, "compare_behavior"},
	"expand_attack_surface": {IntentScopeObservation, "expand_attack_surface"},
	"recheck_inconclusive_path": {IntentClueValidate, "recheck_inconclusive_path"},
	"verify_capability":    {IntentClueValidate, "verify_capability"},
	"promote_capability":   {IntentClueValidate, "promote_capability"},

	// Discovery intents
	"surface_discovery":    {IntentScopeObservation, "surface_discovery"},
	"fingerprint_confirm":  {IntentScopeObservation, "fingerprint_confirm"},
	"js_analysis":          {IntentClueCollect, "js_analysis"},

	// Behavior probing intents
	"behavior_probe":          {IntentClueValidate, "behavior_probe"},
	"auth_probe":              {IntentClueValidate, "auth_probe"},
	"idor_probe":              {IntentClueValidate, "idor_probe"},
	"mass_assignment_probe":   {IntentClueValidate, "mass_assignment_probe"},
	"business_logic_probe":    {IntentClueValidate, "business_logic_probe"},
	"path_traversal_probe":    {IntentClueValidate, "path_traversal_probe"},
	"sqli_probe":              {IntentClueValidate, "sqli_probe"},
	"ssrf_probe":              {IntentClueValidate, "ssrf_probe"},
	"upload_probe":            {IntentClueValidate, "upload_probe"},
	"xss_probe":               {IntentClueValidate, "xss_probe"},
	"ssti_probe":              {IntentClueValidate, "ssti_probe"},
	"command_injection_probe": {IntentClueValidate, "command_injection_probe"},
	"secret_verify":           {IntentClueValidate, "secret_verify"},

	// Code audit intents
	"code_project_index":                  {IntentScopeObservation, "code_project_index"},
	"code_slice_analysis":                 {IntentClueChainExtend, "code_slice_analysis"},
	"route_to_sink_trace":                 {IntentClueChainExtend, "route_to_sink_trace"},
	"entry_to_authz_trace":                {IntentClueChainExtend, "entry_to_authz_trace"},
	"object_owner_check_trace":            {IntentClueChainExtend, "object_owner_check_trace"},
	"mass_assignment_field_trace":         {IntentClueChainExtend, "mass_assignment_field_trace"},
	"file_path_control_trace":             {IntentClueChainExtend, "file_path_control_trace"},
	"upload_to_execution_trace":           {IntentClueChainExtend, "upload_to_execution_trace"},
	"secret_to_privileged_api_trace":      {IntentClueChainExtend, "secret_to_privileged_api_trace"},
	"business_state_transition_trace":     {IntentClueChainExtend, "business_state_transition_trace"},
	"sql_query_construction_trace":        {IntentClueChainExtend, "sql_query_construction_trace"},
	"deserialization_reachability_trace":   {IntentClueChainExtend, "deserialization_reachability_trace"},
	"template_render_reachability_trace":  {IntentClueChainExtend, "template_render_reachability_trace"},
	"ssrf_url_control_trace":              {IntentClueChainExtend, "ssrf_url_control_trace"},

	// Capability / goal
	"capability_expand": {IntentClueChainExtend, "capability_expand"},
	"goal_attempt":      {IntentClueValidate, "goal_attempt"},
}

// modernIntentSet contains the canonical clue-driven intent types.
var modernIntentSet = map[string]bool{
	IntentClueCollect:      true,
	IntentClueValidate:     true,
	IntentClueRefute:       true,
	IntentClueChainExtend:  true,
	IntentScopeObservation: true,
}

// NormalizeIntentType maps a legacy vuln-type intent to its modern clue-driven
// equivalent. Returns (modernType, legacyHint). If the input is already modern,
// it is returned unchanged with an empty hint.
//
// This function is idempotent: NormalizeIntentType(NormalizeIntentType(x)) == NormalizeIntentType(x).
// Unknown intent types are mapped to IntentClueCollect with the original value as hint.
func NormalizeIntentType(intentType string) (modern string, hint string) {
	normalized := strings.ToLower(strings.TrimSpace(intentType))
	if normalized == "" {
		return IntentClueCollect, ""
	}
	// Already modern — pass through
	if modernIntentSet[normalized] {
		return normalized, ""
	}
	// Known legacy mapping
	if entry, ok := legacyIntentMap[normalized]; ok {
		return entry.Modern, entry.Hint
	}
	// Unknown — safe default
	return IntentClueCollect, normalized
}

// IsModernIntentType returns true if the given intent type is in the canonical
// clue-driven set (no normalization needed).
func IsModernIntentType(intentType string) bool {
	return modernIntentSet[strings.ToLower(strings.TrimSpace(intentType))]
}
