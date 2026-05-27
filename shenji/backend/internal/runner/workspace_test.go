package runner

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractZipBlocksTraversalAndExtractsSafeFiles(t *testing.T) {
	root := t.TempDir()
	manager := NewWorkspaceManager(root)
	zipPath := filepath.Join(root, "source.zip")
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	addZipFile(t, writer, "app/main.go", []byte("package main\n"))
	addZipFile(t, writer, "../escape.txt", []byte("bad"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	manifest, err := manager.ExtractZip(context.Background(), 42, zipPath, DefaultExtractLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 1 {
		t.Fatalf("expected one extracted file, got %d", len(manifest.Files))
	}
	if len(manifest.Skipped) != 1 {
		t.Fatalf("expected traversal entry to be skipped, got %d", len(manifest.Skipped))
	}
	if _, err := os.Stat(filepath.Join(root, "escape.txt")); !os.IsNotExist(err) {
		t.Fatalf("traversal file should not exist outside workspace")
	}
	if _, err := os.Stat(filepath.Join(root, "task-42", "input", "extracted", "app", "main.go")); err != nil {
		t.Fatalf("safe file was not extracted: %v", err)
	}
}

func TestExtractZipEnforcesTotalSizeLimit(t *testing.T) {
	root := t.TempDir()
	manager := NewWorkspaceManager(root)
	zipPath := filepath.Join(root, "source.zip")
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	addZipFile(t, writer, "large.txt", bytes.Repeat([]byte("a"), 128))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := manager.ExtractZip(context.Background(), 1, zipPath, ExtractLimits{MaxFiles: 5, MaxFileBytes: 256, MaxTotalBytes: 64})
	if err == nil {
		t.Fatal("expected extraction to fail when total size exceeds limit")
	}
}

func addZipFile(t *testing.T, writer *zip.Writer, name string, content []byte) {
	t.Helper()
	file, err := writer.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}
}
