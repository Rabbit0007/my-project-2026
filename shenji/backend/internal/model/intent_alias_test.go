package model

import (
	"math/rand"
	"testing"
)

func TestNormalizeIntentType_KnownLegacy(t *testing.T) {
	cases := []struct {
		input   string
		wantMod string
		wantHint string
	}{
		{"sql_injection_validation", IntentClueValidate, "sql_injection"},
		{"idor_test", IntentClueValidate, "cross_user_object_access"},
		{"xss_test", IntentClueValidate, "xss"},
		{"ssrf_test", IntentClueValidate, "ssrf"},
		{"rce_test", IntentClueValidate, "rce"},
		{"lfi_test", IntentClueValidate, "lfi"},
		{"xxe_test", IntentClueValidate, "xxe"},
		{"recon", IntentScopeObservation, "recon"},
		{"fingerprint", IntentScopeObservation, "fingerprint"},
		{"code_trace", IntentClueChainExtend, "code_trace"},
		{"dataflow_trace", IntentClueChainExtend, "dataflow_trace"},
		{"inspect_auth_boundary", IntentClueChainExtend, "inspect_auth_boundary"},
		{"inspect_owner_check", IntentClueChainExtend, "inspect_owner_check"},
		{"validate_candidate_path", IntentClueValidate, "validate_candidate_path"},
		{"collect_evidence", IntentClueCollect, "collect_evidence"},
		{"validate", IntentClueValidate, "validate"},
	}
	for _, tc := range cases {
		mod, hint := NormalizeIntentType(tc.input)
		if mod != tc.wantMod {
			t.Errorf("NormalizeIntentType(%q) modern = %q, want %q", tc.input, mod, tc.wantMod)
		}
		if hint != tc.wantHint {
			t.Errorf("NormalizeIntentType(%q) hint = %q, want %q", tc.input, hint, tc.wantHint)
		}
	}
}

func TestNormalizeIntentType_ModernPassthrough(t *testing.T) {
	for _, modern := range []string{
		IntentClueCollect, IntentClueValidate, IntentClueRefute,
		IntentClueChainExtend, IntentScopeObservation,
	} {
		mod, hint := NormalizeIntentType(modern)
		if mod != modern {
			t.Errorf("NormalizeIntentType(%q) = %q, want passthrough", modern, mod)
		}
		if hint != "" {
			t.Errorf("NormalizeIntentType(%q) hint = %q, want empty", modern, hint)
		}
	}
}

func TestNormalizeIntentType_Unknown(t *testing.T) {
	mod, hint := NormalizeIntentType("some_unknown_type")
	if mod != IntentClueCollect {
		t.Errorf("unknown type: modern = %q, want %q", mod, IntentClueCollect)
	}
	if hint != "some_unknown_type" {
		t.Errorf("unknown type: hint = %q, want %q", hint, "some_unknown_type")
	}
}

func TestNormalizeIntentType_Empty(t *testing.T) {
	mod, hint := NormalizeIntentType("")
	if mod != IntentClueCollect {
		t.Errorf("empty: modern = %q, want %q", mod, IntentClueCollect)
	}
	if hint != "" {
		t.Errorf("empty: hint = %q, want empty", hint)
	}
}

func TestNormalizeIntentType_Idempotent(t *testing.T) {
	inputs := []string{
		"sql_injection_validation", "idor_test", "recon", "code_trace",
		"clue_collect", "clue_validate", "unknown_xyz", "",
	}
	for _, input := range inputs {
		first, _ := NormalizeIntentType(input)
		second, _ := NormalizeIntentType(first)
		if first != second {
			t.Errorf("not idempotent: NormalizeIntentType(%q) = %q, NormalizeIntentType(%q) = %q",
				input, first, first, second)
		}
	}
}

func TestNormalizeIntentType_CaseInsensitive(t *testing.T) {
	mod, hint := NormalizeIntentType("SQL_INJECTION_VALIDATION")
	if mod != IntentClueValidate {
		t.Errorf("case insensitive: modern = %q", mod)
	}
	if hint != "sql_injection" {
		t.Errorf("case insensitive: hint = %q", hint)
	}
}

func TestNormalizeIntentType_RandomNoPanic(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	for i := 0; i < 1000; i++ {
		length := r.Intn(50)
		buf := make([]byte, length)
		for j := range buf {
			buf[j] = byte(r.Intn(128))
		}
		// Should not panic
		NormalizeIntentType(string(buf))
	}
}

func TestRequiredClueRoles_Length(t *testing.T) {
	if len(RequiredClueRoles) != 6 {
		t.Errorf("RequiredClueRoles length = %d, want 6", len(RequiredClueRoles))
	}
}
