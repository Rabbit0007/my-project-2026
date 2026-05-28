package config

import (
	"reflect"
	"strings"
	"testing"
)

func removedRepositoryEnvNames() []string {
	return []string{
		strings.Join([]string{"PROOF", "PACKET", "REPOSITORIES"}, "_"),
		strings.Join([]string{"PROOF", "PACKET", "SIDE", "PROBE", "ENABLED"}, "_"),
	}
}

func TestExternalRepositorySideProbeConfigIsRemoved(t *testing.T) {
	cfgType := reflect.TypeOf(Config{})
	for i := 0; i < cfgType.NumField(); i++ {
		fieldName := strings.ToLower(cfgType.Field(i).Name)
		if strings.Contains(fieldName, "proof"+"packet") || strings.Contains(fieldName, "proof"+"_packet") {
			t.Fatalf("removed repository side-probe config field still exists: %s", cfgType.Field(i).Name)
		}
	}
}

func TestExternalRepositorySideProbeEnvDoesNotAffectLoadedConfig(t *testing.T) {
	for _, name := range removedRepositoryEnvNames() {
		t.Setenv(name, "true")
	}

	cfg := Load()
	value := reflect.ValueOf(cfg)
	cfgType := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := cfgType.Field(i)
		if strings.Contains(strings.ToLower(field.Name), "proof") {
			t.Fatalf("removed side-probe env should not populate config field %s", field.Name)
		}
	}
}

func TestCairnCadenceConfigLoadsFromEnv(t *testing.T) {
	t.Setenv("REASON_NO_OP_PASS_BUDGET", "5")
	t.Setenv("NO_PROGRESS_FINALIZE_ROUNDS", "9")
	t.Setenv("PLANNER_NEXT_INTENT_LIMIT", "2")

	cfg := Load()
	if cfg.ReasonNoOpPassBudget != 5 || cfg.NoProgressFinalizeRounds != 9 || cfg.PlannerNextIntentLimit != 2 {
		t.Fatalf("expected cadence env config to load, got reason=%d noProgress=%d plannerLimit=%d",
			cfg.ReasonNoOpPassBudget, cfg.NoProgressFinalizeRounds, cfg.PlannerNextIntentLimit)
	}
}

func TestRuntimeToggleDefaults(t *testing.T) {
	// No env set — should get safe defaults
	cfg := Load()
	if cfg.ClueDrivenPhase != 0 {
		t.Errorf("ClueDrivenPhase default = %d, want 0", cfg.ClueDrivenPhase)
	}
	if cfg.PromotionGate != "legacy" {
		t.Errorf("PromotionGate default = %q, want \"legacy\"", cfg.PromotionGate)
	}
	if cfg.FinalizeMode != "legacy" {
		t.Errorf("FinalizeMode default = %q, want \"legacy\"", cfg.FinalizeMode)
	}
	if cfg.DeliveryWriteback != "off" {
		t.Errorf("DeliveryWriteback default = %q, want \"off\"", cfg.DeliveryWriteback)
	}
}

func TestRuntimeToggleFromEnv(t *testing.T) {
	t.Setenv("RABBIT_CLUE_DRIVEN_PHASE", "3")
	t.Setenv("RABBIT_PROMOTION_GATE", "clue_chain")
	t.Setenv("RABBIT_FINALIZE_FALLBACK", "legacy")
	t.Setenv("RABBIT_DELIVERY_WRITEBACK", "on")

	cfg := Load()
	if cfg.ClueDrivenPhase != 3 {
		t.Errorf("ClueDrivenPhase = %d, want 3", cfg.ClueDrivenPhase)
	}
	if cfg.PromotionGate != "clue_chain" {
		t.Errorf("PromotionGate = %q, want \"clue_chain\"", cfg.PromotionGate)
	}
	if cfg.FinalizeMode != "legacy" {
		t.Errorf("FinalizeMode = %q, want \"legacy\"", cfg.FinalizeMode)
	}
	if cfg.DeliveryWriteback != "on" {
		t.Errorf("DeliveryWriteback = %q, want \"on\"", cfg.DeliveryWriteback)
	}
}
