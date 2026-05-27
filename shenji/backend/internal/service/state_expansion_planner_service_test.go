package service

import (
	"strings"
	"testing"

	"shenji/backend/internal/model"
)

func TestScoreBranchValuePrioritizesTerminalCapability(t *testing.T) {
	hypothesisID := uint(1)
	intent := model.AIIntent{IntentType: model.IntentBehaviorProbe, Objective: "prove admin access"}
	intent.WithValidationMetadata(model.ValidationIntentMetadata{HypothesisID: &hypothesisID, ExpectedCapability: model.CapAdminAccess, SafetyLevel: "authorized_non_destructive"})
	h := model.AIHypothesisNode{
		ID:                 hypothesisID,
		HypothesisType:     model.HypothesisTypeAuthzBypassCandidate,
		Title:              "admin route may be reachable",
		Description:        "validate admin access",
		ExpectedCapability: model.CapAdminAccess,
		TargetEntity:       "/admin",
	}
	pctx := plannerContext{
		GoalProfile: model.AIGoalProfile{GoalType: model.GoalTypeTerminal},
		Environment: map[string]any{},
	}

	score := ScoreBranchValue(model.AISecurityTask{Objective: "prove admin access"}, pctx, h, intent)
	if score.FinalScore < 0.65 {
		t.Fatalf("expected high terminal branch value, got %+v", score)
	}
	if score.CapabilityUnlockScore < 0.95 {
		t.Fatalf("expected high capability score, got %+v", score)
	}
	if !strings.Contains(score.Reason, "terminal goal") || !strings.Contains(score.Reason, model.CapAdminAccess) {
		t.Fatalf("expected terminal explanation, got %q", score.Reason)
	}
}

func TestExpansionGoalCapabilityPrioritizationExplainsObjectiveLadder(t *testing.T) {
	hypothesisID := uint(2)
	intent := model.AIIntent{IntentType: model.IntentCapabilityExpand}
	intent.WithValidationMetadata(model.ValidationIntentMetadata{HypothesisID: &hypothesisID, ExpectedCapability: model.CapCredentialObtained})
	h := model.AIHypothesisNode{
		ID:                 hypothesisID,
		HypothesisType:     model.HypothesisTypeCredentialReuseCandidate,
		Title:              "Secret may unlock identity expansion",
		ExpectedCapability: model.CapCredentialObtained,
		TargetEntity:       "config secret",
	}
	pctx := plannerContext{GoalProfile: model.AIGoalProfile{GoalType: model.GoalTypeExpansion}}

	score := ScoreBranchValue(model.AISecurityTask{}, pctx, h, intent)
	if score.GoalTypeBoost <= 0 {
		t.Fatalf("expected expansion goal boost, got %+v", score)
	}
	if !strings.Contains(score.Reason, "Objective Ladder") || !strings.Contains(score.Reason, model.CapCredentialObtained) {
		t.Fatalf("expected objective ladder explanation, got %q", score.Reason)
	}
}

func TestScoreBranchValuePenalizesNegativeFactDuplicate(t *testing.T) {
	h := model.AIHypothesisNode{
		HypothesisType:     model.HypothesisTypeFileReadCandidate,
		Title:              "Potential arbitrary file read path requires validation",
		ExpectedCapability: model.CapFileRead,
		TargetEntity:       "/download",
	}
	intent := model.AIIntent{IntentType: model.IntentSecretVerify}
	negative := model.AINegativeFact{
		ID:                77,
		TestedPath:        "/download",
		SimilarPatternKey: hypothesisPatternKey(h.HypothesisType, h.TargetEntity, h.Title),
	}
	pctx := plannerContext{
		GoalProfile:   model.AIGoalProfile{GoalType: model.GoalTypeCoverage},
		NegativeFacts: []model.AINegativeFact{negative},
	}

	score := ScoreBranchValue(model.AISecurityTask{}, pctx, h, intent)
	if score.DuplicatePenalty < 0.9 {
		t.Fatalf("expected duplicate penalty, got %+v", score)
	}
	if score.FinalScore > 0.55 {
		t.Fatalf("expected duplicate branch to be deprioritized, got %+v", score)
	}
	if len(score.NegativeFactRefs) != 1 || score.NegativeFactRefs[0] != 77 {
		t.Fatalf("expected negative fact ref 77, got %+v", score.NegativeFactRefs)
	}
	if !strings.Contains(score.Reason, "NegativeFact 77") {
		t.Fatalf("expected negative fact reason, got %q", score.Reason)
	}
}

func TestNegativeFactPenaltyRanksBelowEquivalentUnpenalizedIntent(t *testing.T) {
	h := model.AIHypothesisNode{
		HypothesisType:     model.HypothesisTypeSSRFCandidate,
		Title:              "Potential SSRF path requires validation",
		ExpectedCapability: model.CapInternalServiceAccess,
		TargetEntity:       "/fetch?url=",
	}
	intent := model.AIIntent{IntentType: model.IntentSSRFProbe}
	negative := model.AINegativeFact{
		ID:                101,
		TestedPath:        h.TargetEntity,
		SimilarPatternKey: hypothesisPatternKey(h.HypothesisType, h.TargetEntity, h.Title),
	}
	base := plannerContext{GoalProfile: model.AIGoalProfile{GoalType: model.GoalTypeCoverage}}
	penalized := base
	penalized.NegativeFacts = []model.AINegativeFact{negative}

	cleanScore := ScoreBranchValue(model.AISecurityTask{}, base, h, intent)
	penalizedScore := ScoreBranchValue(model.AISecurityTask{}, penalized, h, intent)
	if penalizedScore.FinalScore >= cleanScore.FinalScore {
		t.Fatalf("expected negative fact to lower ranking: clean=%+v penalized=%+v", cleanScore, penalizedScore)
	}
}

func TestEnvironmentAlignmentBoostsGraphExpansion(t *testing.T) {
	h := model.AIHypothesisNode{
		HypothesisType:     model.HypothesisTypeLateralAccessCandidate,
		Title:              "Kubernetes service account may enable namespace discovery",
		Description:        "validate service account access",
		ExpectedCapability: model.CapInternalServiceAccess,
	}
	strong := environmentAlignment(h, map[string]any{"orchestration_layer": map[string]any{"kubernetes": model.ConfidenceStrong}})
	suspected := environmentAlignment(h, map[string]any{"orchestration_layer": map[string]any{"kubernetes": model.ConfidenceSuspected}})
	if strong.Boost <= suspected.Boost {
		t.Fatalf("expected strong environment alignment to exceed suspected: strong=%+v suspected=%+v", strong, suspected)
	}
	if len(strong.Refs) == 0 || !strings.Contains(strong.Reason, "kubernetes") {
		t.Fatalf("expected auditable environment refs/reason, got %+v", strong)
	}
}

func TestConfirmedAndValidatedEnvironmentScoreNoLowerThanStrong(t *testing.T) {
	h := model.AIHypothesisNode{
		HypothesisType:     model.HypothesisTypeLateralAccessCandidate,
		Title:              "Kubernetes namespace service account validation",
		ExpectedCapability: model.CapInternalServiceAccess,
	}
	strong := environmentAlignment(h, map[string]any{"orchestration_layer": map[string]any{"kubernetes": model.ConfidenceStrong}})
	confirmed := environmentAlignment(h, map[string]any{"orchestration_layer": map[string]any{"kubernetes": model.ConfidenceConfirmed}})
	validated := environmentAlignment(h, map[string]any{"orchestration_layer": map[string]any{"kubernetes": model.ConfidenceValidated}})
	if confirmed.Boost < strong.Boost || validated.Boost < strong.Boost {
		t.Fatalf("expected confirmed/validated no lower than strong: strong=%+v confirmed=%+v validated=%+v", strong, confirmed, validated)
	}
}

func TestCoverageDoesNotDominateCapabilityUnlock(t *testing.T) {
	coverageHeavy := model.AIHypothesisNode{
		HypothesisType:     model.HypothesisTypeBusinessLogicCandidate,
		Title:              "Checkout coupon coverage gap",
		ExpectedCapability: "",
		TargetEntity:       "/checkout/coupon",
	}
	capabilityHeavy := model.AIHypothesisNode{
		HypothesisType:     model.HypothesisTypeCommandExecutionCandidate,
		Title:              "Command execution branch",
		ExpectedCapability: model.CapCommandExecution,
		TargetEntity:       "/admin/import",
	}
	pctx := plannerContext{
		GoalProfile: model.AIGoalProfile{GoalType: model.GoalTypeCoverage},
		CoverageItems: []model.AICoverageItem{{
			Name:      "coupon",
			TargetRef: "/checkout/coupon",
			Status:    "discovered",
		}},
	}

	a := ScoreBranchValue(model.AISecurityTask{}, pctx, coverageHeavy, model.AIIntent{IntentType: model.IntentBehaviorProbe})
	b := ScoreBranchValue(model.AISecurityTask{}, pctx, capabilityHeavy, model.AIIntent{IntentType: model.IntentBehaviorProbe})
	if b.FinalScore <= a.FinalScore {
		t.Fatalf("expected capability-heavy branch to outrank coverage-heavy branch: coverage=%+v capability=%+v", a, b)
	}
	if DefaultStateExpansionScoringWeights().CoverageGain >= DefaultStateExpansionScoringWeights().Novelty {
		t.Fatalf("coverage weight must stay secondary: %+v", DefaultStateExpansionScoringWeights())
	}
}

func TestRefutedEnvironmentSignalLowersScore(t *testing.T) {
	h := model.AIHypothesisNode{
		HypothesisType:     model.HypothesisTypeLateralAccessCandidate,
		Title:              "Kubernetes service account may enable namespace discovery",
		Description:        "validate namespace service account",
		ExpectedCapability: model.CapInternalServiceAccess,
	}
	intent := model.AIIntent{IntentType: model.IntentCapabilityExpand}
	strong := plannerContext{
		GoalProfile: model.AIGoalProfile{GoalType: model.GoalTypeExpansion},
		Environment: map[string]any{"orchestration_layer": map[string]any{"kubernetes": model.ConfidenceStrong}},
	}
	refuted := plannerContext{
		GoalProfile: model.AIGoalProfile{GoalType: model.GoalTypeExpansion},
		Environment: map[string]any{"orchestration_layer": map[string]any{"kubernetes": model.ConfidenceRefuted}},
	}

	strongScore := ScoreBranchValue(model.AISecurityTask{}, strong, h, intent)
	refutedScore := ScoreBranchValue(model.AISecurityTask{}, refuted, h, intent)
	if refutedScore.EnvironmentAlignmentBoost >= 0 {
		t.Fatalf("expected refuted environment signal to lower boost, got %+v", refutedScore)
	}
	if strongScore.FinalScore <= refutedScore.FinalScore {
		t.Fatalf("expected refuted environment to lower score: strong=%+v refuted=%+v", strongScore, refutedScore)
	}
	if !strings.Contains(refutedScore.Reason, "refutes") {
		t.Fatalf("expected refuted environment reason, got %q", refutedScore.Reason)
	}
}

func TestEvidenceQualityIsNotConstant(t *testing.T) {
	bare := model.AIIntent{Objective: "validate candidate"}
	rich := model.AIIntent{
		Objective: "validate candidate with reproducible proof condition",
		RequiredEvidence: model.JSONValue([]string{
			"baseline evidence",
			"response_diff",
			"raw request",
			"raw response",
			"successful marker",
		}),
	}
	if expectedEvidenceQuality(rich) <= expectedEvidenceQuality(bare) {
		t.Fatalf("expected rich evidence plan to score higher: bare=%f rich=%f", expectedEvidenceQuality(bare), expectedEvidenceQuality(rich))
	}
}

func TestNoveltyScoreIsNotConstant(t *testing.T) {
	newBranch := model.AIHypothesisNode{
		HypothesisType:     model.HypothesisTypeSSRFCandidate,
		Title:              "New URL parameter SSRF candidate",
		ExpectedCapability: model.CapInternalServiceAccess,
		TargetEntity:       "/webhook?url=",
	}
	repeatedBranch := model.AIHypothesisNode{
		HypothesisType:     model.HypothesisTypeSSRFCandidate,
		Title:              "New URL parameter SSRF candidate",
		ExpectedCapability: model.CapInternalServiceAccess,
		TargetEntity:       "/webhook?url=",
	}
	cap := model.AICapability{CapabilityType: model.CapInternalServiceAccess, Target: "/webhook?url="}
	negative := model.AINegativeFact{
		TestedPath:        "/webhook?url=",
		SimilarPatternKey: hypothesisPatternKey(repeatedBranch.HypothesisType, repeatedBranch.TargetEntity, repeatedBranch.Title),
	}
	newScore := noveltyScore(newBranch, nil, nil)
	repeatedScore := noveltyScore(repeatedBranch, []model.AICapability{cap}, []model.AINegativeFact{negative})
	if newScore <= repeatedScore {
		t.Fatalf("expected new branch to have higher novelty: new=%f repeated=%f", newScore, repeatedScore)
	}
}

func TestBranchValueFinalScoreEqualsIntentPriorityAssignment(t *testing.T) {
	h := model.AIHypothesisNode{
		HypothesisType:     model.HypothesisTypeCommandExecutionCandidate,
		Title:              "Command execution branch",
		ExpectedCapability: model.CapCommandExecution,
		TargetEntity:       "/import",
	}
	intent := model.AIIntent{IntentType: model.IntentCommandInjProbe}
	score := ScoreBranchValue(model.AISecurityTask{}, plannerContext{GoalProfile: model.AIGoalProfile{GoalType: model.GoalTypeCoverage}}, h, intent)
	intent.PriorityScore = score.FinalScore
	if err := intent.WithBranchValue(score); err != nil {
		t.Fatalf("unexpected branch value write error: %v", err)
	}
	got, err := intent.BranchValue()
	if err != nil {
		t.Fatalf("unexpected branch value read error: %v", err)
	}
	if got == nil || got.FinalScore != intent.PriorityScore {
		t.Fatalf("expected branch final score to match priority: branch=%+v priority=%f", got, intent.PriorityScore)
	}
}

func TestDefaultWeightsKeepCoverageSecondary(t *testing.T) {
	weights := DefaultStateExpansionScoringWeights()
	if !(weights.CapabilityUnlock >= weights.GraphExpansion &&
		weights.GraphExpansion >= weights.RiskValue &&
		weights.RiskValue >= weights.Novelty &&
		weights.Novelty > weights.CoverageGain) {
		t.Fatalf("weights violate planner ordering principle: %+v", weights)
	}
}
