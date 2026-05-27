package runner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"shenji/backend/internal/config"
)

type RunRequest struct {
	TaskID        uint
	RunnerType    string
	ToolName      string
	ImageName     string
	WorkspacePath string
	Command       []string
	Timeout       time.Duration
	NetworkPolicy string
}

type RunResult struct {
	ContainerID    string
	ImageName      string
	CommandPreview string
	Stdout         string
	Stderr         string
	ExitCode       int
	Status         string
	StartedAt      time.Time
	FinishedAt     time.Time
}

type WorkerContainerExecRequest struct {
	TaskID        uint
	Command       []string
	Env           []string
	Timeout       time.Duration
	WorkingDir    string
	NetworkPolicy string
}

type RunnerManager struct {
	cfg    config.Config
	docker *dockerRuntime
}

func NewRunnerManager(cfg config.Config) *RunnerManager {
	runtime, err := newDockerRuntime(cfg)
	if err != nil {
		return &RunnerManager{cfg: cfg}
	}
	return &RunnerManager{cfg: cfg, docker: runtime}
}

func (m *RunnerManager) ExecInTaskWorkerContainer(ctx context.Context, req WorkerContainerExecRequest) (RunResult, error) {
	if m.docker == nil {
		return RunResult{}, fmt.Errorf("docker runtime is unavailable")
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = m.cfg.ToolTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return m.docker.execInTaskWorkerContainer(runCtx, req)
}

func (m *RunnerManager) StopTaskWorkerContainer(ctx context.Context, taskID uint) error {
	if m.docker == nil {
		return nil
	}
	return m.docker.stopTaskWorkerContainer(ctx, taskID)
}

func (m *RunnerManager) Run(ctx context.Context, req RunRequest) RunResult {
	started := time.Now().UTC()
	if len(req.Command) == 0 {
		finished := time.Now().UTC()
		return RunResult{
			ImageName:      req.ImageName,
			CommandPreview: "",
			Stderr:         "runner command is empty",
			ExitCode:       1,
			Status:         "failed",
			StartedAt:      started,
			FinishedAt:     finished,
		}
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = m.cfg.ToolTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if req.RunnerType == "sandbox" && m.docker != nil {
		result, err := m.docker.runSandboxContainer(runCtx, req)
		if err == nil {
			return result
		}
		return RunResult{
			ImageName:      req.ImageName,
			CommandPreview: strings.Join(req.Command, " "),
			Stderr:         fmt.Sprintf("docker sandbox runner failed: %v", err),
			ExitCode:       1,
			Status:         "failed",
			StartedAt:      started,
			FinishedAt:     time.Now().UTC(),
		}
	}

	if req.RunnerType == "code_audit" && m.docker != nil {
		result, err := m.docker.runCodeAuditContainer(runCtx, req)
		if err == nil {
			return result
		}
		return RunResult{
			ImageName:      req.ImageName,
			CommandPreview: strings.Join(req.Command, " "),
			Stderr:         fmt.Sprintf("docker code-audit runner failed: %v", err),
			ExitCode:       1,
			Status:         "failed",
			StartedAt:      started,
			FinishedAt:     time.Now().UTC(),
		}
	}

	if req.RunnerType == "pentest" && m.docker != nil {
		result, err := m.docker.runPentestContainer(runCtx, req)
		if err == nil {
			return result
		}
		return RunResult{
			ImageName:      req.ImageName,
			CommandPreview: strings.Join(req.Command, " "),
			Stderr:         fmt.Sprintf("docker pentest runner failed: %v", err),
			ExitCode:       1,
			Status:         "failed",
			StartedAt:      started,
			FinishedAt:     time.Now().UTC(),
		}
	}

	// First-stage implementation executes only platform-owned safe utilities.
	// Docker images are wired in compose and this seam can be switched to Docker SDK without changing ToolRun persistence.
	cmd := exec.CommandContext(runCtx, req.Command[0], req.Command[1:]...)
	if req.WorkspacePath != "" {
		cmd.Dir = req.WorkspacePath
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	finished := time.Now().UTC()
	result := RunResult{
		ImageName:      req.ImageName,
		CommandPreview: strings.Join(req.Command, " "),
		Stdout:         stdout.String(),
		Stderr:         stderr.String(),
		ExitCode:       0,
		Status:         "success",
		StartedAt:      started,
		FinishedAt:     finished,
	}
	if err != nil {
		result.Status = "failed"
		if runCtx.Err() == context.DeadlineExceeded {
			result.Status = "timeout"
			result.Stderr += "\nrunner timeout exceeded"
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = 1
			result.Stderr += fmt.Sprintf("\n%v", err)
		}
	}
	return result
}
