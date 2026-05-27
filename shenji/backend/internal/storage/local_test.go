package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalStoreDeletePrefixRemovesTaskArtifactsOnly(t *testing.T) {
	root := t.TempDir()
	store, err := NewLocalStore(root, "")
	if err != nil {
		t.Fatalf("create local store: %v", err)
	}
	if _, _, err := store.PutText(context.Background(), "task-1/reports/report.md", "report"); err != nil {
		t.Fatalf("put task artifact: %v", err)
	}
	if _, _, err := store.PutText(context.Background(), "task-2/reports/report.md", "other"); err != nil {
		t.Fatalf("put other task artifact: %v", err)
	}

	if err := store.DeletePrefix(context.Background(), "task-1/"); err != nil {
		t.Fatalf("delete prefix: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "task-1", "reports", "report.md")); !os.IsNotExist(err) {
		t.Fatalf("task-1 artifact should be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "task-2", "reports", "report.md")); err != nil {
		t.Fatalf("task-2 artifact should remain: %v", err)
	}
}

func TestLocalStoreDeletePrefixRejectsEmptyPrefix(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), "")
	if err != nil {
		t.Fatalf("create local store: %v", err)
	}
	if err := store.DeletePrefix(context.Background(), ""); err == nil {
		t.Fatalf("expected empty prefix to be rejected")
	}
	if err := store.DeletePrefix(context.Background(), "../task-1"); err == nil {
		t.Fatalf("expected traversal prefix to be rejected")
	}
}
