package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ArtifactStore interface {
	PutText(ctx context.Context, key string, content string) (string, string, error)
	PutBytes(ctx context.Context, key string, content []byte) (string, string, error)
	ReadText(ctx context.Context, ref string) (string, error)
	PublicURL(ref string) string
	DeletePrefix(ctx context.Context, prefix string) error
}

type LocalStore struct {
	root      string
	publicURL string
}

func NewLocalStore(root string, publicURL string) (*LocalStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &LocalStore{root: root, publicURL: strings.TrimRight(publicURL, "/")}, nil
}

func (s *LocalStore) PutText(ctx context.Context, key string, content string) (string, string, error) {
	return s.PutBytes(ctx, key, []byte(content))
}

func (s *LocalStore) PutBytes(ctx context.Context, key string, content []byte) (string, string, error) {
	_ = ctx
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	cleanKey, err := cleanArtifactKey(key)
	if err != nil || cleanKey == "" {
		cleanKey = fmt.Sprintf("artifact-%d.txt", time.Now().UnixNano())
	}
	path := filepath.Join(s.root, cleanKey)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return "", "", err
	}
	return "local://" + cleanKey, hash, nil
}

func (s *LocalStore) ReadText(ctx context.Context, ref string) (string, error) {
	_ = ctx
	key := strings.TrimPrefix(ref, "local://")
	cleanKey, err := cleanArtifactKey(key)
	if err != nil {
		return "", err
	}
	content, err := os.ReadFile(filepath.Join(s.root, cleanKey))
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (s *LocalStore) PublicURL(ref string) string {
	key := strings.TrimPrefix(ref, "local://")
	if s.publicURL == "" {
		return ref
	}
	return s.publicURL + "/artifacts/" + key
}

func (s *LocalStore) DeletePrefix(ctx context.Context, prefix string) error {
	_ = ctx
	cleanPrefix, err := cleanArtifactKey(prefix)
	if err != nil || cleanPrefix == "" {
		return fmt.Errorf("artifact prefix is empty")
	}
	return os.RemoveAll(filepath.Join(s.root, cleanPrefix))
}

func cleanArtifactKey(key string) (string, error) {
	normalized := strings.ReplaceAll(key, "\\", "/")
	parts := strings.Split(normalized, "/")
	cleanParts := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "", ".":
			continue
		case "..":
			return "", fmt.Errorf("artifact key must not contain path traversal")
		default:
			cleanParts = append(cleanParts, part)
		}
	}
	if len(cleanParts) == 0 {
		return "", nil
	}
	return filepath.Join(cleanParts...), nil
}
