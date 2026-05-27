package database

import (
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"shenji/backend/internal/config"
	"shenji/backend/internal/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Connect(cfg config.Config) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.DatabaseDSN), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("obtain sql db: %w", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	return db, nil
}

func AutoMigrate(db *gorm.DB) error {
	// Register global callback to sanitize UTF-8 strings before writing to PostgreSQL
	db.Callback().Create().Before("gorm:create").Register("sanitize_utf8", sanitizeUTF8Callback)
	db.Callback().Update().Before("gorm:update").Register("sanitize_utf8", sanitizeUTF8Callback)

	return db.AutoMigrate(
		&model.AIUser{},
		&model.AIWorkspace{},
		&model.AISecurityTask{},
		&model.AITaskTarget{},
		&model.AIAgentLoop{},
		&model.AIAgentLoopIteration{},
		&model.AIBlackboardNode{},
		&model.AIBlackboardEdge{},
		&model.AIIntent{},
		&model.AIToolRun{},
		&model.AIEvidence{},
		&model.AIFinding{},
		&model.AIContractCheckResult{},
		&model.AIReport{},
		&model.AIHumanReview{},
		&model.AIModelConfig{},
		&model.AIAuditEvent{},
		&model.AIModelCallLog{},
		&model.AICapability{},
		&model.AIGoalProfile{},
		&model.AIHypothesisNode{},
		&model.AINegativeFact{},
		&model.AIUnverifiedRisk{},
		&model.AICoverageItem{},
		&model.AIEnvironmentModel{},
		&model.AIObjectiveLadder{},
	)
}

// sanitizeUTF8Callback cleans invalid UTF-8 sequences from all string fields
// before writing to PostgreSQL, preventing "invalid byte sequence for encoding UTF8" errors.
func sanitizeUTF8Callback(db *gorm.DB) {
	if db.Statement == nil || db.Statement.Dest == nil {
		return
	}
	val := reflect.ValueOf(db.Statement.Dest)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return
	}
	sanitizeStructFields(val)
}

func sanitizeStructFields(val reflect.Value) {
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		if !field.CanSet() {
			continue
		}
		// Skip password hash fields — bcrypt hashes contain valid bytes that look like invalid UTF-8
		fieldName := typ.Field(i).Name
		if fieldName == "PasswordHash" {
			continue
		}
		switch field.Kind() {
		case reflect.String:
			s := field.String()
			if s != "" && !utf8.ValidString(s) {
				field.SetString(cleanUTF8(s))
			}
		case reflect.Ptr:
			if !field.IsNil() && field.Elem().Kind() == reflect.String {
				s := field.Elem().String()
				if s != "" && !utf8.ValidString(s) {
					cleaned := cleanUTF8(s)
					field.Elem().SetString(cleaned)
				}
			}
		}
	}
}

func cleanUTF8(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			i++
			continue
		}
		if r == 0 {
			i++
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}
