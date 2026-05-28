package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment              string
	ServerAddr               string
	DatabaseDSN              string
	RedisAddr                string
	WorkspaceRoot            string
	HostWorkspaceRoot        string
	ArtifactRoot             string
	ArtifactStoreType        string
	RunnerImagesRoot         string
	CodeAuditRunnerImage     string
	PentestRunnerImage       string
	PiWorkerImage            string
	PiWorkerNetworkMode      string
	PiWorkerTimeout          time.Duration
	SandboxRunnerImage       string
	MinIOEndpoint            string
	MinIOAccessKey           string
	MinIOSecretKey           string
	MinIOBucket              string
	MinIOUseSSL              bool
	PublicBaseURL            string
	CORSOrigins              []string
	ModelTimeout             time.Duration
	ToolTimeout              time.Duration
	SandboxTimeout           time.Duration
	WorkerLease              time.Duration
	MaxIterations            int
	MaxRuntime               time.Duration
	MaxToolRuns              int
	MaxPendingIntents        int
	ReasonNoOpPassBudget     int
	NoProgressFinalizeRounds int
	PlannerNextIntentLimit   int
	CodeAuditMaxHits         int
	CodeAuditMaxSnippets     int
	CodeAuditBatchSize       int
	CodeAuditMaxBatches      int

	// Clue-driven runtime toggles (Phase 0+)
	ClueDrivenPhase   int    // env RABBIT_CLUE_DRIVEN_PHASE, default 0
	PromotionGate     string // env RABBIT_PROMOTION_GATE, default "clue_chain"
	FinalizeMode      string // env RABBIT_FINALIZE_FALLBACK, default "legacy"
	DeliveryWriteback string // env RABBIT_DELIVERY_WRITEBACK, default "off"
}

func Load() Config {
	port := getenv("BACKEND_PORT", "18080")
	return Config{
		Environment:              getenv("APP_ENV", "development"),
		ServerAddr:               ":" + port,
		DatabaseDSN:              getenv("DATABASE_DSN", "host=localhost user=shenji password=shenji dbname=shenji port=15432 sslmode=disable TimeZone=UTC"),
		RedisAddr:                getenv("REDIS_ADDR", "localhost:16379"),
		WorkspaceRoot:            getenv("WORKSPACE_ROOT", "./workspace"),
		HostWorkspaceRoot:        getenv("HOST_WORKSPACE_ROOT", "./workspace"),
		ArtifactRoot:             getenv("ARTIFACT_ROOT", "./workspace/artifacts"),
		ArtifactStoreType:        getenv("ARTIFACT_STORE_TYPE", "minio"),
		RunnerImagesRoot:         getenv("RUNNER_IMAGES_ROOT", "../runner-images"),
		CodeAuditRunnerImage:     getenv("CODE_AUDIT_RUNNER_IMAGE", "rabbit-runner-code-audit:local"),
		PentestRunnerImage:       getenv("PENTEST_RUNNER_IMAGE", "rabbit-runner-pentest:local"),
		PiWorkerImage:            getenv("PI_WORKER_IMAGE", "rabbit-pi-worker-kali:local"),
		PiWorkerNetworkMode:      getenv("PI_WORKER_NETWORK_MODE", "bridge"),
		PiWorkerTimeout:          durationFromSeconds("PI_WORKER_TIMEOUT_SECONDS", 360),
		SandboxRunnerImage:       getenv("SANDBOX_RUNNER_IMAGE", "rabbit-runner-sandbox:local"),
		MinIOEndpoint:            getenv("MINIO_ENDPOINT", "localhost:19110"),
		MinIOAccessKey:           getenv("MINIO_ACCESS_KEY", "minioadmin"),
		MinIOSecretKey:           getenv("MINIO_SECRET_KEY", "minioadmin"),
		MinIOBucket:              getenv("MINIO_BUCKET", "rabbit-artifacts"),
		MinIOUseSSL:              boolFromEnv("MINIO_USE_SSL", false),
		PublicBaseURL:            getenv("PUBLIC_BASE_URL", "http://localhost:"+port),
		CORSOrigins:              splitCSV(getenv("CORS_ORIGINS", "http://localhost:13000,http://127.0.0.1:13000")),
		ModelTimeout:             durationFromSeconds("MODEL_TIMEOUT_SECONDS", 90),
		ToolTimeout:              durationFromSeconds("TOOL_TIMEOUT_SECONDS", 180),
		SandboxTimeout:           durationFromSeconds("SANDBOX_TIMEOUT_SECONDS", 300),
		WorkerLease:              durationFromSeconds("WORKER_LEASE_TIMEOUT_SECONDS", 120),
		MaxIterations:            intFromEnv("MAX_ITERATIONS", 12),
		MaxRuntime:               durationFromMinutes("MAX_RUNTIME_MINUTES", 45),
		MaxToolRuns:              intFromEnv("MAX_TOOL_RUNS", 120),
		MaxPendingIntents:        intFromEnv("MAX_PENDING_INTENTS", 40),
		ReasonNoOpPassBudget:     intFromEnv("REASON_NO_OP_PASS_BUDGET", 4),
		NoProgressFinalizeRounds: intFromEnv("NO_PROGRESS_FINALIZE_ROUNDS", 6),
		PlannerNextIntentLimit:   intFromEnv("PLANNER_NEXT_INTENT_LIMIT", 3),
		CodeAuditMaxHits:         intFromEnv("CODE_AUDIT_MAX_HITS", 3000),
		CodeAuditMaxSnippets:     intFromEnv("CODE_AUDIT_MAX_SNIPPETS", 420),
		CodeAuditBatchSize:       intFromEnv("CODE_AUDIT_BATCH_SIZE", 6),
		CodeAuditMaxBatches:      intFromEnv("CODE_AUDIT_MAX_BATCHES", 80),

		// Clue-driven runtime toggles
		ClueDrivenPhase:   intFromEnv("RABBIT_CLUE_DRIVEN_PHASE", 0),
		PromotionGate:     getenv("RABBIT_PROMOTION_GATE", "legacy"),
		FinalizeMode:      getenv("RABBIT_FINALIZE_FALLBACK", "legacy"),
		DeliveryWriteback: getenv("RABBIT_DELIVERY_WRITEBACK", "off"),
	}
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func intFromEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func durationFromSeconds(key string, fallback int) time.Duration {
	return time.Duration(intFromEnv(key, fallback)) * time.Second
}

func durationFromMinutes(key string, fallback int) time.Duration {
	return time.Duration(intFromEnv(key, fallback)) * time.Minute
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func boolFromEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
