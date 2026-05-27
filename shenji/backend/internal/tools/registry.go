package tools

import (
	"shenji/backend/internal/config"
	"shenji/backend/internal/runner"
)

func DefaultRegistry(cfg config.Config, manager *runner.RunnerManager) *ToolRegistry {
	registry := NewRegistry()
	registry.Register(NewHTTPRequestTool(cfg.ToolTimeout, manager))
	registry.Register(HTTPSurfaceTool{})
	registry.Register(NewPentestProbeTool(manager, cfg.ToolTimeout))
	registry.Register(NewFingerprintTool(manager, cfg.ToolTimeout))
	registry.Register(NewSurfaceDiscoveryTool(manager, cfg.ToolTimeout))
	registry.Register(NewBehaviorProbeTool(manager, cfg.ToolTimeout))
	registry.Register(NewBrowserRunnerTool(manager, cfg.ToolTimeout))
	registry.Register(ResponseDiffTool{})
	registry.Register(NewCodeSearchTool(manager, cfg.ToolTimeout))
	registry.Register(NewCodeSliceTool(manager, cfg.ToolTimeout))
	registry.Register(NewCodeProjectIndexTool(manager, cfg.ToolTimeout))
	registry.Register(NewSandboxExecTool(manager, cfg.SandboxTimeout))
	registry.Register(ReportAssemblerTool{})
	return registry
}
