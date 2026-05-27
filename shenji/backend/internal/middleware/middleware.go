package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// AuthValidator is a function that validates a token and returns userID, username, role.
type AuthValidator func(token string) (uint, string, string, error)

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Info().
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Int("status", c.Writer.Status()).
			Dur("latency", time.Since(start)).
			Msg("http request")
	}
}

func Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered any) {
		log.Error().Any("panic", recovered).Msg("panic recovered")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	})
}

func CORS(origins []string) gin.HandlerFunc {
	allowed := map[string]bool{}
	for _, origin := range origins {
		allowed[origin] = true
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if allowed[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
		}
		c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type,Authorization")
		c.Header("Access-Control-Allow-Credentials", "true")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// Auth returns a middleware that validates Bearer tokens.
func Auth(validate AuthValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录，请先登录"})
			c.Abort()
			return
		}
		token := strings.TrimPrefix(header, "Bearer ")
		if token == header {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的认证格式"})
			c.Abort()
			return
		}
		userID, username, role, err := validate(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "认证已过期，请重新登录"})
			c.Abort()
			return
		}
		c.Set("userID", userID)
		c.Set("username", username)
		c.Set("role", role)
		c.Next()
	}
}

func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := map[string]bool{}
	for _, role := range roles {
		allowed[strings.ToLower(strings.TrimSpace(role))] = true
	}
	return func(c *gin.Context) {
		role, _ := c.Get("role")
		roleText, _ := role.(string)
		if !allowed[strings.ToLower(strings.TrimSpace(roleText))] {
			c.JSON(http.StatusForbidden, gin.H{"error": "没有权限执行此操作"})
			c.Abort()
			return
		}
		c.Next()
	}
}
