package runner

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type WorkspaceManager struct {
	Root string
}

type ExtractManifest struct {
	Files        []string `json:"files"`
	Skipped      []string `json:"skipped"`
	TotalBytes   int64    `json:"totalBytes"`
	ExtractedDir string   `json:"extractedDir"`
}

type ExtractLimits struct {
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
}

func DefaultExtractLimits() ExtractLimits {
	return ExtractLimits{
		MaxFiles:      12000,
		MaxFileBytes:  16 << 20,
		MaxTotalBytes: 256 << 20,
	}
}

func NewWorkspaceManager(root string) *WorkspaceManager {
	return &WorkspaceManager{Root: root}
}

func (m *WorkspaceManager) TaskRoot(taskID uint) string {
	return filepath.Join(m.Root, fmt.Sprintf("task-%d", taskID))
}

func (m *WorkspaceManager) PrepareTask(ctx context.Context, taskID uint) (string, error) {
	_ = ctx
	root := m.TaskRoot(taskID)
	dirs := []string{
		filepath.Join(root, "input"),
		filepath.Join(root, "input", "extracted"),
		filepath.Join(root, "work"),
		filepath.Join(root, "artifacts"),
		filepath.Join(root, "evidence"),
		filepath.Join(root, "logs"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	return root, nil
}

func (m *WorkspaceManager) SaveUpload(ctx context.Context, taskID uint, fileName string, reader io.Reader) (string, error) {
	_ = ctx
	root, err := m.PrepareTask(ctx, taskID)
	if err != nil {
		return "", err
	}
	target := filepath.Join(root, "input", safeBase(fileName))
	out, err := os.Create(target)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, io.LimitReader(reader, 512<<20)); err != nil {
		return "", err
	}
	return target, nil
}

func (m *WorkspaceManager) ExtractZip(ctx context.Context, taskID uint, zipPath string, limits ExtractLimits) (ExtractManifest, error) {
	_ = ctx
	root, err := m.PrepareTask(ctx, taskID)
	if err != nil {
		return ExtractManifest{}, err
	}
	dest := filepath.Join(root, "input", "extracted")
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return ExtractManifest{}, err
	}
	defer reader.Close()

	manifest := ExtractManifest{ExtractedDir: dest, Files: []string{}, Skipped: []string{}}
	if len(reader.File) > limits.MaxFiles {
		return manifest, fmt.Errorf("zip contains too many files: %d > %d", len(reader.File), limits.MaxFiles)
	}
	for _, file := range reader.File {
		if err := ctx.Err(); err != nil {
			return manifest, err
		}
		name := filepath.Clean(file.Name)
		if name == "." || strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			manifest.Skipped = append(manifest.Skipped, file.Name+": path traversal blocked")
			continue
		}
		info := file.FileInfo()
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeDevice != 0 {
			manifest.Skipped = append(manifest.Skipped, file.Name+": special file skipped")
			continue
		}
		if info.Size() > limits.MaxFileBytes {
			manifest.Skipped = append(manifest.Skipped, file.Name+": file too large")
			continue
		}
		if manifest.TotalBytes+info.Size() > limits.MaxTotalBytes {
			return manifest, fmt.Errorf("zip total extracted bytes exceeds limit")
		}
		target := filepath.Join(dest, name)
		if !strings.HasPrefix(target, dest+string(filepath.Separator)) && target != dest {
			manifest.Skipped = append(manifest.Skipped, file.Name+": zip slip blocked")
			continue
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return manifest, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return manifest, err
		}
		src, err := file.Open()
		if err != nil {
			return manifest, err
		}
		func() {
			defer src.Close()
			out, createErr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
			if createErr != nil {
				err = createErr
				return
			}
			defer out.Close()
			_, err = io.Copy(out, io.LimitReader(src, limits.MaxFileBytes+1))
		}()
		if err != nil {
			return manifest, err
		}
		manifest.TotalBytes += info.Size()
		manifest.Files = append(manifest.Files, name)
	}
	return manifest, nil
}

func safeBase(name string) string {
	base := filepath.Base(name)
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, base)
	if base == "." || base == "" {
		return "upload.zip"
	}
	return base
}
