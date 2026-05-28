package service

import (
	"encoding/json"

	"shenji/backend/internal/model"

	"gorm.io/datatypes"
)

// normalizeIntentBeforeCreate applies NormalizeIntentType to an AIIntent before
// persisting it. Only active when ClueDrivenPhase >= 3. The original IntentType
// is preserved in ConstraintsJSON.legacy_hint for backward compatibility and
// worker routing.
//
// This function modifies the intent in-place and returns true if normalization
// was applied (for audit purposes).
func normalizeIntentBeforeCreate(intent *model.AIIntent, phase int) (normalized bool, originalType string, hint string) {
	if phase < 3 || intent == nil {
		return false, "", ""
	}
	originalType = intent.IntentType
	modern, legacyHint := model.NormalizeIntentType(intent.IntentType)
	if legacyHint == "" {
		// Already modern, no normalization needed
		return false, originalType, ""
	}
	intent.IntentType = modern

	// Preserve legacy_hint in ConstraintsJSON
	constraints := map[string]any{}
	if len(intent.ConstraintsJSON) > 0 {
		_ = json.Unmarshal(intent.ConstraintsJSON, &constraints)
	}
	constraints["legacy_hint"] = legacyHint
	raw, _ := json.Marshal(constraints)
	intent.ConstraintsJSON = datatypes.JSON(raw)

	return true, originalType, legacyHint
}
