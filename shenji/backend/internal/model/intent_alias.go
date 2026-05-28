package model

import "strings"

// legacyIntentMap maps legacy vuln-type intent names to their modern clue-driven
// equivalents. The second value is the legacy_hint to preserve in ConstraintsJSON.
var legacyIntentMap = map[string]struct {
	Modern string
	Hint   string
}{
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
