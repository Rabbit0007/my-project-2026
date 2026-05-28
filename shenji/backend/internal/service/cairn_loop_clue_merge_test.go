package service

import (
	"context"
	"encoding/json"
	"testing"

	"shenji/backend/internal/model"
)

func TestGraphDeltaClueFacts_WritesCorrectNodeType(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9301)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)

	delta := GraphDelta{
		IntentID: 1,
		NewClueFacts: []ClueFact{
			{NodeKind: model.NodeClueOrigin, Title: "GET /api/items", Summary: "entry point", Roles: []string{model.RoleOriginOrEntry}, EvidenceIDs: []uint{10}, SourceIntent: 1, Extra: map[string]any{"custom": "value"}},
			{NodeKind: model.NodeClueObservation, Title: "param id controllable", Summary: "trigger", Roles: []string{model.RoleTriggerOrControl}},
		},
	}
	if err := loop.ApplyGraphDelta(ctx, taskID, delta); err != nil {
		t.Fatalf("ApplyGraphDelta: %v", err)
	}

	var nodes []model.AIBlackboardNode
	db.Where("task_id = ? AND node_type IN ?", taskID, []string{model.NodeClueOrigin, model.NodeClueObservation}).Find(&nodes)
	if len(nodes) < 2 {
		t.Fatalf("expected at least 2 clue nodes, got %d", len(nodes))
	}

	// Verify first node
	var found bool
	for _, n := range nodes {
		if n.Title == "GET /api/items" && n.NodeType == model.NodeClueOrigin {
			found = true
			var content map[string]any
			_ = json.Unmarshal(n.ContentJSON, &content)
			roles, _ := content["roles"].([]any)
			if len(roles) == 0 {
				t.Error("expected roles in ContentJSON")
			}
			if content["source_intent_id"] == nil {
				t.Error("expected source_intent_id in ContentJSON")
			}
			if content["custom"] != "value" {
				t.Error("expected extra fields preserved in ContentJSON")
			}
		}
	}
	if !found {
		t.Error("clue_origin node with correct title not found")
	}
}

func TestGraphDeltaClueChainLinks_WritesCorrectEdgeType(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9302)
	bb := NewBlackboardService(db)
	loop := NewCairnLoop(db, bb, NewIntentService(db), nil, nil, nil, nil, nil, nil)

	// Create two nodes to link
	n1, _ := bb.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeClueOrigin, Title: "source node", DedupSeed: "src", ImportanceScore: 0.8, SourceType: "test", SourceID: "t1"})
	n2, _ := bb.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeClueObservation, Title: "target node", DedupSeed: "tgt", ImportanceScore: 0.7, SourceType: "test", SourceID: "t2"})

	delta := GraphDelta{
		IntentID: 2,
		ClueChainLinks: []ClueChainLink{
			{FromCluePath: "source node", ToCluePath: "target node", LinkKind: "data_flow", Roles: []string{model.RoleReachabilityOrRelation}, EvidenceIDs: []uint{20}},
		},
	}
	if err := loop.ApplyGraphDelta(ctx, taskID, delta); err != nil {
		t.Fatalf("ApplyGraphDelta: %v", err)
	}

	var edges []model.AIBlackboardEdge
	db.Where("task_id = ? AND from_id = ? AND to_id = ?", taskID, n1.ID, n2.ID).Find(&edges)
	if len(edges) == 0 {
		t.Fatal("expected edge between source and target nodes")
	}
	if edges[0].EdgeType != model.EdgeClueChainsTo {
		t.Errorf("expected EdgeType=%s, got %s", model.EdgeClueChainsTo, edges[0].EdgeType)
	}
}

func TestGraphDeltaRefutedClues_WritesNodeAndEdge(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9303)
	bb := NewBlackboardService(db)
	loop := NewCairnLoop(db, bb, NewIntentService(db), nil, nil, nil, nil, nil, nil)

	// Create target node to refute
	target, _ := bb.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeClueObservation, Title: "suspected vuln path", DedupSeed: "suspect1", ImportanceScore: 0.8, SourceType: "test", SourceID: "t1"})

	delta := GraphDelta{
		IntentID: 3,
		RefutedClues: []ClueRefutation{
			{TargetNodeID: target.ID, Reason: "owner check present", EvidenceIDs: []uint{30}},
		},
	}
	if err := loop.ApplyGraphDelta(ctx, taskID, delta); err != nil {
		t.Fatalf("ApplyGraphDelta: %v", err)
	}

	// Verify clue_refuted node was created
	var refutedNodes []model.AIBlackboardNode
	db.Where("task_id = ? AND node_type = ?", taskID, model.NodeClueRefuted).Find(&refutedNodes)
	if len(refutedNodes) == 0 {
		t.Fatal("expected clue_refuted node")
	}

	// Verify clue_refutes edge
	var edges []model.AIBlackboardEdge
	db.Where("task_id = ? AND edge_type = ?", taskID, model.EdgeClueRefutes).Find(&edges)
	if len(edges) == 0 {
		t.Fatal("expected clue_refutes edge")
	}
	if edges[0].ToID != target.ID {
		t.Errorf("expected edge to target %d, got %d", target.ID, edges[0].ToID)
	}
}

func TestGraphDeltaRefutedClues_SuppressesTargetNotDeletes(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9304)
	bb := NewBlackboardService(db)
	loop := NewCairnLoop(db, bb, NewIntentService(db), nil, nil, nil, nil, nil, nil)

	// Create target node
	target, _ := bb.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeClueObservation, Title: "path to suppress", DedupSeed: "supp1", ImportanceScore: 0.9, SourceType: "test", SourceID: "t1"})

	delta := GraphDelta{
		IntentID: 4,
		RefutedClues: []ClueRefutation{
			{TargetNodeID: target.ID, Reason: "guard effective"},
		},
	}
	_ = loop.ApplyGraphDelta(ctx, taskID, delta)

	// Target should be suppressed, NOT deleted
	var node model.AIBlackboardNode
	if err := db.First(&node, target.ID).Error; err != nil {
		t.Fatal("target node was deleted — should only be suppressed")
	}
	if node.Status != model.BlackboardNodeStatusSuppressed {
		t.Errorf("expected status=suppressed, got %s", node.Status)
	}
}

func TestGraphDeltaRefutedClues_ByDedupKey(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9305)
	bb := NewBlackboardService(db)
	loop := NewCairnLoop(db, bb, NewIntentService(db), nil, nil, nil, nil, nil, nil)

	// Create target with known dedup_key
	target, _ := bb.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeClueObservation, Title: "some path", DedupSeed: "stable-key-123", ImportanceScore: 0.8, SourceType: "test", SourceID: "t1"})

	delta := GraphDelta{
		IntentID: 5,
		RefutedClues: []ClueRefutation{
			{TargetDedupKey: target.DedupKey, Reason: "not reachable"},
		},
	}
	_ = loop.ApplyGraphDelta(ctx, taskID, delta)

	var node model.AIBlackboardNode
	db.First(&node, target.ID)
	if node.Status != model.BlackboardNodeStatusSuppressed {
		t.Errorf("expected suppressed via dedup_key, got %s", node.Status)
	}
}

func TestGraphDeltaRefutedClues_TitleFallbackAmbiguous_NoSuppress(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9306)
	bb := NewBlackboardService(db)
	loop := NewCairnLoop(db, bb, NewIntentService(db), nil, nil, nil, nil, nil, nil)

	// Create two nodes with same title (ambiguous)
	bb.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeClueObservation, Title: "ambiguous title", DedupSeed: "amb1", ImportanceScore: 0.8, SourceType: "test", SourceID: "t1"})
	bb.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeClueObservation, Title: "ambiguous title", DedupSeed: "amb2", ImportanceScore: 0.7, SourceType: "test", SourceID: "t2"})

	delta := GraphDelta{
		IntentID: 6,
		RefutedClues: []ClueRefutation{
			{TargetCluePath: "ambiguous title", Reason: "ambiguous"},
		},
	}
	_ = loop.ApplyGraphDelta(ctx, taskID, delta)

	// Neither node should be suppressed (ambiguous = no action)
	var nodes []model.AIBlackboardNode
	db.Where("task_id = ? AND title = ? AND status = ?", taskID, "ambiguous title", model.BlackboardNodeStatusActive).Find(&nodes)
	if len(nodes) != 2 {
		t.Errorf("expected both ambiguous nodes to remain active, got %d active", len(nodes))
	}
}

func TestGraphDelta_NewClueFacts_TakesPriorityOverNewFacts(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9307)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)

	delta := GraphDelta{
		IntentID: 7,
		NewClueFacts: []ClueFact{
			{NodeKind: model.NodeClueOrigin, Title: "clue primary", Summary: "from structured field", Roles: []string{model.RoleOriginOrEntry}},
		},
		NewFacts: []GraphFact{
			{NodeType: "fact", Title: "legacy fact", Summary: "from legacy field"},
		},
	}
	if err := loop.ApplyGraphDelta(ctx, taskID, delta); err != nil {
		t.Fatalf("ApplyGraphDelta: %v", err)
	}

	// Both should exist in DB
	var clueNode model.AIBlackboardNode
	db.Where("task_id = ? AND title = ?", taskID, "clue primary").First(&clueNode)
	if clueNode.ID == 0 {
		t.Fatal("expected clue primary node from NewClueFacts")
	}
	if clueNode.NodeType != model.NodeClueOrigin {
		t.Errorf("expected NodeType=%s, got %s", model.NodeClueOrigin, clueNode.NodeType)
	}

	var legacyNode model.AIBlackboardNode
	db.Where("task_id = ? AND title = ?", taskID, "legacy fact").First(&legacyNode)
	if legacyNode.ID == 0 {
		t.Fatal("expected legacy fact node from NewFacts (observation-only)")
	}
	// Legacy node should have its original NodeType (not clue_*)
	if legacyNode.NodeType == model.NodeClueOrigin || legacyNode.NodeType == model.NodeClueObservation {
		t.Errorf("legacy fact should NOT get clue_* NodeType, got %s", legacyNode.NodeType)
	}
}

func TestGraphDelta_ClueDeltaIngestedAudit(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9308)
	loop := NewCairnLoop(db, NewBlackboardService(db), NewIntentService(db), nil, nil, nil, nil, nil, nil)

	delta := GraphDelta{
		IntentID: 8,
		NewClueFacts: []ClueFact{
			{NodeKind: model.NodeClueObservation, Title: "obs1", Summary: "s1"},
			{NodeKind: model.NodeClueObservation, Title: "obs2", Summary: "s2"},
		},
	}
	_ = loop.ApplyGraphDelta(ctx, taskID, delta)

	var audit model.AIAuditEvent
	err := db.Where("task_id = ? AND event_type = ?", taskID, "agent.clue_delta_ingested").First(&audit).Error
	if err != nil {
		t.Fatal("expected agent.clue_delta_ingested audit event")
	}
	var meta map[string]any
	_ = json.Unmarshal(audit.Metadata, &meta)
	if meta["new_clue_facts"] == nil {
		t.Error("expected new_clue_facts count in audit metadata")
	}
}

func TestResolveClueNodeID_ByDedupKey(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9309)
	bb := NewBlackboardService(db)
	loop := NewCairnLoop(db, bb, nil, nil, nil, nil, nil, nil, nil)

	node, _ := bb.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeClueOrigin, Title: "test node", DedupSeed: "my-stable-key", ImportanceScore: 0.8, SourceType: "test", SourceID: "t1"})

	// Resolve by dedup_key
	resolved := loop.resolveClueNodeID(ctx, taskID, node.DedupKey)
	if resolved != node.ID {
		t.Errorf("expected resolve by dedup_key to return %d, got %d", node.ID, resolved)
	}
}

func TestResolveClueNodeID_UniqueTitle(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9310)
	bb := NewBlackboardService(db)
	loop := NewCairnLoop(db, bb, nil, nil, nil, nil, nil, nil, nil)

	node, _ := bb.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeClueOrigin, Title: "unique title here", DedupSeed: "uniq1", ImportanceScore: 0.8, SourceType: "test", SourceID: "t1"})

	resolved := loop.resolveClueNodeID(ctx, taskID, "unique title here")
	if resolved != node.ID {
		t.Errorf("expected resolve by unique title to return %d, got %d", node.ID, resolved)
	}
}

func TestResolveClueNodeID_AmbiguousTitle_ReturnsZero(t *testing.T) {
	db := newRegressionTestDB(t)
	ctx := context.Background()
	taskID := uint(9311)
	bbs := NewBlackboardService(db)
	loop := NewCairnLoop(db, bbs, nil, nil, nil, nil, nil, nil, nil)

	bbs.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeClueOrigin, Title: "dup title", DedupSeed: "d1", ImportanceScore: 0.8, SourceType: "test", SourceID: "t1"})
	bbs.UpsertNode(ctx, BlackboardNodeDraft{TaskID: taskID, NodeType: model.NodeClueOrigin, Title: "dup title", DedupSeed: "d2", ImportanceScore: 0.7, SourceType: "test", SourceID: "t2"})

	resolved := loop.resolveClueNodeID(ctx, taskID, "dup title")
	if resolved != 0 {
		t.Errorf("expected 0 for ambiguous title, got %d", resolved)
	}
}
