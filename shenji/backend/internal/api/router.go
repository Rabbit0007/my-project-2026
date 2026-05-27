package api

import (
	"fmt"
	"net/http"
	"path"
	"strings"

	"shenji/backend/internal/config"
	"shenji/backend/internal/middleware"
	"shenji/backend/internal/service"

	"github.com/gin-gonic/gin"
)

func NewRouter(cfg config.Config, services *service.Services) *gin.Engine {
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(middleware.Recovery(), middleware.RequestLogger(), middleware.CORS(cfg.CORSOrigins))
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	serveArtifact := func(c *gin.Context) {
		ref := strings.TrimPrefix(c.Param("filepath"), "/")
		if ref == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing artifact path"})
			return
		}
		if strings.HasPrefix(ref, cfg.MinIOBucket+"/") {
			ref = "minio://" + ref
		} else if !strings.HasPrefix(ref, "minio://") {
			ref = "local://" + ref
		}
		content, err := services.Store.ReadText(c.Request.Context(), ref)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "artifact not found"})
			return
		}
		contentType := "text/plain; charset=utf-8"
		if strings.HasSuffix(ref, ".html") {
			contentType = "text/html; charset=utf-8"
		} else if strings.HasSuffix(ref, ".json") {
			contentType = "application/json"
		} else if strings.HasSuffix(ref, ".md") {
			contentType = "text/markdown; charset=utf-8"
		}
		if strings.EqualFold(c.Query("download"), "1") || strings.EqualFold(c.Query("download"), "true") {
			filename := path.Base(ref)
			if filename == "." || filename == "/" || strings.TrimSpace(filename) == "" {
				filename = "rabbit-report"
			}
			c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
			c.Header("X-Content-Type-Options", "nosniff")
		}
		c.Header("Content-Length", fmt.Sprintf("%d", len(content)))
		if c.Request.Method == http.MethodHead {
			c.Status(http.StatusOK)
			return
		}
		c.Data(http.StatusOK, contentType, []byte(content))
	}
	r.GET("/artifacts/*filepath", serveArtifact)
	r.HEAD("/artifacts/*filepath", serveArtifact)

	handler := NewHandler(services)

	// Auth token validator
	authValidator := func(token string) (uint, string, string, error) {
		payload, err := services.Auth.ValidateToken(token)
		if err != nil {
			return 0, "", "", err
		}
		return payload.UserID, payload.Username, payload.Role, nil
	}

	// Public auth routes (no token required)
	auth := r.Group("/api/v1/auth")
	{
		auth.POST("/login", handler.Login)
	}

	// Protected API routes
	v1 := r.Group("/api/v1")
	v1.Use(middleware.Auth(authValidator))
	{
		// Auth management
		v1.GET("/auth/me", handler.GetCurrentUser)
		v1.POST("/auth/change-password", handler.ChangePassword)

		// AI Chat
		v1.POST("/chat", handler.Chat)

		v1.GET("/overview", handler.Overview)
		v1.GET("/tools", handler.Tools)
		v1.GET("/tasks", handler.ListTasks)
		v1.GET("/tasks/:id", handler.GetTask)
		v1.GET("/tasks/:id/timeline", handler.TaskTimeline)
		v1.GET("/tasks/:id/tool-runs", handler.TaskToolRuns)
		v1.GET("/tasks/:id/evidence", handler.TaskEvidence)
		v1.GET("/tasks/:id/findings", handler.TaskFindings)
		v1.GET("/findings", handler.ListFindings)
		v1.GET("/findings/:id", handler.GetFinding)
		v1.GET("/tasks/:id/capabilities", handler.TaskCapabilities)
		v1.GET("/tasks/:id/reports", handler.TaskReports)
		v1.GET("/reports", handler.ListReports)

		// Data export
		v1.GET("/tasks/:id/export/findings", handler.ExportFindings)
		v1.GET("/tasks/:id/export/evidence", handler.ExportEvidence)

		admin := v1.Group("")
		admin.Use(middleware.RequireRole("admin"))
		{
			admin.GET("/model-configs", handler.ListModelConfigs)
			admin.POST("/model-configs", handler.CreateModelConfig)
			admin.PATCH("/model-configs/:id", handler.UpdateModelConfig)
			admin.POST("/model-configs/:id/test", handler.TestModelConfig)
			admin.POST("/tasks", handler.CreateTask)
			admin.POST("/tasks/:id/start", handler.StartTask)
			admin.POST("/tasks/:id/upload", handler.UploadZip)
			admin.POST("/tasks/:id/reports/regenerate", handler.RegenerateTaskReport)
			admin.DELETE("/tasks/:id", handler.DeleteTask)
			admin.POST("/tasks/:id/restart", handler.RestartTask)
			// User management
			admin.GET("/users", handler.ListUsers)
			admin.POST("/users", handler.CreateUser)
			admin.PATCH("/users/:id", handler.UpdateUser)

			// Audit log
			admin.GET("/audit-events", handler.ListAuditEvents)

			// Model call logs
			admin.GET("/model-call-logs", handler.ListModelCallLogs)
		}
	}
	return r
}
