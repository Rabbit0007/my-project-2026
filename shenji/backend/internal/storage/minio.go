package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"shenji/backend/internal/config"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type MinIOStore struct {
	client     *minio.Client
	bucketName string
	publicURL  string
}

func NewMinIOStore(ctx context.Context, cfg config.Config) (*MinIOStore, error) {
	client, err := minio.New(cfg.MinIOEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinIOAccessKey, cfg.MinIOSecretKey, ""),
		Secure: cfg.MinIOUseSSL,
	})
	if err != nil {
		return nil, err
	}
	exists, err := client.BucketExists(ctx, cfg.MinIOBucket)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := client.MakeBucket(ctx, cfg.MinIOBucket, minio.MakeBucketOptions{}); err != nil {
			return nil, err
		}
	}
	return &MinIOStore{
		client:     client,
		bucketName: cfg.MinIOBucket,
		publicURL:  strings.TrimRight(cfg.PublicBaseURL, "/"),
	}, nil
}

func (s *MinIOStore) PutText(ctx context.Context, key string, content string) (string, string, error) {
	return s.PutBytes(ctx, key, []byte(content))
}

func (s *MinIOStore) PutBytes(ctx context.Context, key string, content []byte) (string, string, error) {
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	objectKey, err := cleanArtifactKey(key)
	if err != nil || objectKey == "" {
		return "", "", fmt.Errorf("invalid artifact key")
	}
	objectKey = strings.ReplaceAll(objectKey, "\\", "/")
	_, err = s.client.PutObject(ctx, s.bucketName, objectKey, bytes.NewReader(content), int64(len(content)), minio.PutObjectOptions{
		ContentType: detectContentType(objectKey),
	})
	if err != nil {
		return "", "", err
	}
	return "minio://" + s.bucketName + "/" + objectKey, hash, nil
}

func (s *MinIOStore) ReadText(ctx context.Context, ref string) (string, error) {
	bucket, objectKey, err := parseMinIORef(ref)
	if err != nil {
		return "", err
	}
	object, err := s.client.GetObject(ctx, bucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		return "", err
	}
	defer object.Close()
	content, err := io.ReadAll(object)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (s *MinIOStore) PublicURL(ref string) string {
	bucket, objectKey, err := parseMinIORef(ref)
	if err != nil {
		return ref
	}
	return s.publicURL + "/artifacts/" + bucket + "/" + objectKey
}

func (s *MinIOStore) DeletePrefix(ctx context.Context, prefix string) error {
	objectPrefix, err := cleanArtifactKey(prefix)
	if err != nil || strings.TrimSpace(objectPrefix) == "" {
		return fmt.Errorf("artifact prefix is empty")
	}
	objectPrefix = strings.ReplaceAll(objectPrefix, "\\", "/")
	if !strings.HasSuffix(objectPrefix, "/") {
		objectPrefix += "/"
	}
	for object := range s.client.ListObjects(ctx, s.bucketName, minio.ListObjectsOptions{Prefix: objectPrefix, Recursive: true}) {
		if object.Err != nil {
			return object.Err
		}
		if err := s.client.RemoveObject(ctx, s.bucketName, object.Key, minio.RemoveObjectOptions{}); err != nil {
			return err
		}
	}
	return nil
}

func parseMinIORef(ref string) (string, string, error) {
	trimmed := strings.TrimPrefix(ref, "minio://")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid minio ref: %s", ref)
	}
	return parts[0], parts[1], nil
}

func detectContentType(key string) string {
	switch {
	case strings.HasSuffix(key, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(key, ".md"), strings.HasSuffix(key, ".txt"), strings.HasSuffix(key, ".log"):
		return "text/plain; charset=utf-8"
	case strings.HasSuffix(key, ".json"):
		return "application/json"
	default:
		return "application/octet-stream"
	}
}
