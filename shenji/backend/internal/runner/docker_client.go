package runner

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shenji/backend/internal/config"

	"github.com/docker/docker/api/types/build"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

type dockerRuntime struct {
	cfg config.Config
	cli *client.Client
}

func newDockerRuntime(cfg config.Config) (*dockerRuntime, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &dockerRuntime{cfg: cfg, cli: cli}, nil
}

func (d *dockerRuntime) ensureRunnerImage(ctx context.Context, tag string, runnerDir string) (string, error) {
	_, _, err := d.cli.ImageInspectWithRaw(ctx, tag)
	if err == nil {
		return tag, nil
	}

	contextRoot := filepath.Join(d.cfg.RunnerImagesRoot, runnerDir)
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	if err := filepath.Walk(contextRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(contextRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = rel
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			if _, err := io.Copy(tw, file); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return "", err
	}
	if err := tw.Close(); err != nil {
		return "", err
	}

	response, err := d.cli.ImageBuild(ctx, bytes.NewReader(buf.Bytes()), build.ImageBuildOptions{
		Tags:       []string{tag},
		Dockerfile: "Dockerfile",
		Remove:     true,
	})
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return tag, nil
}

func (d *dockerRuntime) runSandboxContainer(ctx context.Context, req RunRequest) (RunResult, error) {
	imageName, err := d.ensureRunnerImage(ctx, d.cfg.SandboxRunnerImage, "sandbox")
	if err != nil {
		return RunResult{}, err
	}
	return d.runTaskContainer(ctx, req, imageName, "sandbox-runner", "/workspace/work", req.NetworkPolicy)
}

func (d *dockerRuntime) runCodeAuditContainer(ctx context.Context, req RunRequest) (RunResult, error) {
	imageName, err := d.ensureRunnerImage(ctx, d.cfg.CodeAuditRunnerImage, "code-audit")
	if err != nil {
		return RunResult{}, err
	}
	return d.runTaskContainer(ctx, req, imageName, "code-audit-runner", "/workspace/input/extracted", "none")
}

func (d *dockerRuntime) runPentestContainer(ctx context.Context, req RunRequest) (RunResult, error) {
	imageName, err := d.ensureRunnerImage(ctx, d.cfg.PentestRunnerImage, "pentest")
	if err != nil {
		return RunResult{}, err
	}
	return d.runTaskContainer(ctx, req, imageName, "pentest-runner", "/workspace/work", "bridge")
}

func (d *dockerRuntime) runTaskContainer(ctx context.Context, req RunRequest, imageName string, namePrefix string, workingDir string, networkPolicy string) (RunResult, error) {
	mounts, err := d.taskWorkspaceMounts(req.TaskID)
	if err != nil {
		return RunResult{}, err
	}
	networkMode := runnerNetworkMode(networkPolicy)
	extraHosts := runnerExtraHosts(networkMode)
	containerName := fmt.Sprintf("%s-%d-%d", namePrefix, req.TaskID, time.Now().UnixNano())
	started := time.Now().UTC()
	resp, err := d.cli.ContainerCreate(ctx, &container.Config{
		Image:      imageName,
		Cmd:        req.Command,
		WorkingDir: workingDir,
		Tty:        false,
	}, &container.HostConfig{
		AutoRemove:  false,
		NetworkMode: networkMode,
		ExtraHosts:  extraHosts,
		Mounts:      mounts,
		Resources: container.Resources{
			Memory:    256 << 20,
			NanoCPUs:  500000000,
			PidsLimit: int64Ptr(64),
		},
	}, nil, nil, containerName)
	if err != nil {
		return RunResult{}, err
	}
	containerID := resp.ID
	defer func() {
		timeout := 2 * time.Second
		_ = d.cli.ContainerStop(context.Background(), containerID, container.StopOptions{Timeout: &[]int{int(timeout.Seconds())}[0]})
		_ = d.cli.ContainerRemove(context.Background(), containerID, container.RemoveOptions{Force: true})
	}()

	if err := d.cli.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
		return RunResult{}, err
	}

	waitCh, errCh := d.cli.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	exitCode := int64(1)
	status := "failed"
	select {
	case wait := <-waitCh:
		exitCode = wait.StatusCode
		if exitCode == 0 {
			status = "success"
		}
	case waitErr := <-errCh:
		if waitErr != nil {
			return RunResult{}, waitErr
		}
	case <-ctx.Done():
		status = "timeout"
	}

	logReader, err := d.cli.ContainerLogs(context.Background(), containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return RunResult{}, err
	}
	defer logReader.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdoutBuf, &stderrBuf, logReader); err != nil {
		return RunResult{}, err
	}
	return RunResult{
		ContainerID:    containerID,
		ImageName:      imageName,
		CommandPreview: strings.Join(req.Command, " "),
		Stdout:         stdoutBuf.String(),
		Stderr:         stderrBuf.String(),
		ExitCode:       int(exitCode),
		Status:         status,
		StartedAt:      started,
		FinishedAt:     time.Now().UTC(),
	}, nil
}

func (d *dockerRuntime) execInTaskWorkerContainer(ctx context.Context, req WorkerContainerExecRequest) (RunResult, error) {
	if len(req.Command) == 0 {
		return RunResult{}, fmt.Errorf("worker container command is empty")
	}
	imageName, err := d.ensureRunnerImage(ctx, d.cfg.PiWorkerImage, "pi-worker-kali")
	if err != nil {
		return RunResult{}, err
	}
	containerID, err := d.ensureTaskWorkerContainer(ctx, req.TaskID, imageName, firstNonEmpty(req.NetworkPolicy, d.cfg.PiWorkerNetworkMode))
	if err != nil {
		return RunResult{}, err
	}
	workingDir := firstNonEmpty(req.WorkingDir, "/workspace/work")
	started := time.Now().UTC()
	execResp, err := d.cli.ContainerExecCreate(ctx, containerID, container.ExecOptions{
		Cmd:          req.Command,
		Env:          req.Env,
		WorkingDir:   workingDir,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	})
	if err != nil {
		return RunResult{}, err
	}
	attach, err := d.cli.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{Tty: false})
	if err != nil {
		return RunResult{}, err
	}
	defer attach.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	copyDone := make(chan error, 1)
	go func() {
		_, copyErr := stdcopy.StdCopy(&stdoutBuf, &stderrBuf, attach.Reader)
		copyDone <- copyErr
	}()
	if err := d.cli.ContainerExecStart(ctx, execResp.ID, container.ExecStartOptions{Tty: false}); err != nil {
		return RunResult{}, err
	}
	var copyErr error
	select {
	case copyErr = <-copyDone:
	case <-ctx.Done():
		timeout := 1
		_ = d.cli.ContainerStop(context.Background(), containerID, container.StopOptions{Timeout: &timeout})
		attach.Close()
		select {
		case copyErr = <-copyDone:
		case <-time.After(2 * time.Second):
		}
		return RunResult{
			ContainerID:    containerID,
			ImageName:      imageName,
			CommandPreview: strings.Join(req.Command, " "),
			Stdout:         stdoutBuf.String(),
			Stderr:         stderrBuf.String(),
			ExitCode:       124,
			Status:         "timeout",
			StartedAt:      started,
			FinishedAt:     time.Now().UTC(),
		}, ctx.Err()
	}
	if copyErr != nil {
		return RunResult{}, copyErr
	}
	inspect, err := d.cli.ContainerExecInspect(context.Background(), execResp.ID)
	if err != nil {
		return RunResult{}, err
	}
	status := "failed"
	if inspect.ExitCode == 0 {
		status = "success"
	}
	if ctx.Err() == context.DeadlineExceeded {
		status = "timeout"
	}
	return RunResult{
		ContainerID:    containerID,
		ImageName:      imageName,
		CommandPreview: strings.Join(req.Command, " "),
		Stdout:         stdoutBuf.String(),
		Stderr:         stderrBuf.String(),
		ExitCode:       inspect.ExitCode,
		Status:         status,
		StartedAt:      started,
		FinishedAt:     time.Now().UTC(),
	}, nil
}

func (d *dockerRuntime) ensureTaskWorkerContainer(ctx context.Context, taskID uint, imageName string, networkPolicy string) (string, error) {
	name := taskWorkerContainerName(taskID)
	inspect, err := d.cli.ContainerInspect(ctx, name)
	if err == nil {
		if inspect.State != nil && inspect.State.Running {
			return inspect.ID, nil
		}
		if startErr := d.cli.ContainerStart(ctx, inspect.ID, container.StartOptions{}); startErr != nil {
			return "", startErr
		}
		return inspect.ID, nil
	}
	mounts, err := d.taskWorkspaceMounts(taskID)
	if err != nil {
		return "", err
	}
	networkMode := runnerNetworkMode(networkPolicy)
	resp, err := d.cli.ContainerCreate(ctx, &container.Config{
		Image:      imageName,
		Cmd:        []string{"sleep", "infinity"},
		WorkingDir: "/workspace/work",
		Tty:        false,
	}, &container.HostConfig{
		AutoRemove:  false,
		NetworkMode: networkMode,
		ExtraHosts:  runnerExtraHosts(networkMode),
		Mounts:      mounts,
		Resources: container.Resources{
			Memory:    2 << 30,
			NanoCPUs:  2000000000,
			PidsLimit: int64Ptr(512),
		},
	}, nil, nil, name)
	if err != nil {
		return "", err
	}
	if err := d.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func (d *dockerRuntime) stopTaskWorkerContainer(ctx context.Context, taskID uint) error {
	name := taskWorkerContainerName(taskID)
	inspect, err := d.cli.ContainerInspect(ctx, name)
	if err != nil {
		return nil
	}
	timeout := 2
	if inspect.State != nil && inspect.State.Running {
		_ = d.cli.ContainerStop(ctx, inspect.ID, container.StopOptions{Timeout: &timeout})
	}
	return d.cli.ContainerRemove(ctx, inspect.ID, container.RemoveOptions{Force: true})
}

func (d *dockerRuntime) taskWorkspaceMounts(taskID uint) ([]mount.Mount, error) {
	taskRoot := filepath.Join(d.cfg.HostWorkspaceRoot, fmt.Sprintf("task-%d", taskID))
	for _, dir := range []string{"input", "work", "artifacts", "evidence", "logs"} {
		if err := os.MkdirAll(filepath.Join(taskRoot, dir), 0o755); err != nil {
			return nil, err
		}
	}
	return []mount.Mount{
		{Type: mount.TypeBind, Source: filepath.Join(taskRoot, "input"), Target: "/workspace/input", ReadOnly: true},
		{Type: mount.TypeBind, Source: filepath.Join(taskRoot, "work"), Target: "/workspace/work"},
		{Type: mount.TypeBind, Source: filepath.Join(taskRoot, "artifacts"), Target: "/workspace/artifacts"},
		{Type: mount.TypeBind, Source: filepath.Join(taskRoot, "evidence"), Target: "/workspace/evidence"},
		{Type: mount.TypeBind, Source: filepath.Join(taskRoot, "logs"), Target: "/workspace/logs"},
	}, nil
}

func taskWorkerContainerName(taskID uint) string {
	return fmt.Sprintf("rabbit-pi-worker-task-%d", taskID)
}

func runnerNetworkMode(policy string) container.NetworkMode {
	policy = strings.ToLower(strings.TrimSpace(policy))
	if policy == "" || policy == "bridge" || strings.Contains(policy, "authorized-scope-only") {
		return container.NetworkMode("bridge")
	}
	if policy == "host" {
		return container.NetworkMode("host")
	}
	if policy == "none" || strings.Contains(policy, "none") {
		return container.NetworkMode("none")
	}
	return container.NetworkMode(policy)
}

func runnerExtraHosts(networkMode container.NetworkMode) []string {
	if networkMode == "none" || networkMode == "host" {
		return nil
	}
	return []string{"host.docker.internal:host-gateway"}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func int64Ptr(value int64) *int64 {
	return &value
}
