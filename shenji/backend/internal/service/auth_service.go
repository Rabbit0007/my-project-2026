package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"shenji/backend/internal/model"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService struct {
	db     *gorm.DB
	secret []byte
}

type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ChangePasswordInput struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

type AuthToken struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

type tokenPayload struct {
	UserID   uint   `json:"uid"`
	Username string `json:"usr"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"`
}

func NewAuthService(db *gorm.DB) *AuthService {
	secret := []byte(os.Getenv("JWT_SECRET"))
	if len(secret) == 0 {
		secret = []byte("rabbit-shenji-default-secret-change-me")
	}
	return &AuthService{db: db, secret: secret}
}

// EnsureDefaultUser creates a default admin user if no users exist.
func (s *AuthService) EnsureDefaultUser(ctx context.Context) error {
	var count int64
	if err := s.db.WithContext(ctx).Model(&model.AIUser{}).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user := model.AIUser{
		Username:     "admin",
		PasswordHash: string(hash),
		DisplayName:  "管理员",
		Role:         "admin",
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	return s.db.WithContext(ctx).Create(&user).Error
}

func (s *AuthService) Login(ctx context.Context, input LoginInput) (AuthToken, error) {
	username := strings.TrimSpace(input.Username)
	password := strings.TrimSpace(input.Password)
	if username == "" || password == "" {
		return AuthToken{}, fmt.Errorf("用户名和密码不能为空")
	}

	var user model.AIUser
	if err := s.db.WithContext(ctx).Where("username = ? AND enabled = ?", username, true).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return AuthToken{}, fmt.Errorf("用户名或密码错误")
		}
		return AuthToken{}, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return AuthToken{}, fmt.Errorf("用户名或密码错误")
	}

	// Update last login
	now := time.Now().UTC()
	user.LastLoginAt = &now
	_ = s.db.WithContext(ctx).Save(&user).Error

	// Generate token (24h expiry)
	expiresAt := now.Add(24 * time.Hour).Unix()
	payload := tokenPayload{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		Exp:      expiresAt,
	}
	token, err := s.signToken(payload)
	if err != nil {
		return AuthToken{}, err
	}

	return AuthToken{Token: token, ExpiresAt: expiresAt}, nil
}

func (s *AuthService) ChangePassword(ctx context.Context, userID uint, input ChangePasswordInput) error {
	oldPwd := strings.TrimSpace(input.OldPassword)
	newPwd := strings.TrimSpace(input.NewPassword)
	if oldPwd == "" || newPwd == "" {
		return fmt.Errorf("密码不能为空")
	}
	if len(newPwd) < 6 {
		return fmt.Errorf("新密码长度不能少于6位")
	}

	var user model.AIUser
	if err := s.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		return fmt.Errorf("用户不存在")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPwd)); err != nil {
		return fmt.Errorf("原密码错误")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPwd), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.PasswordHash = string(hash)
	user.UpdatedAt = time.Now().UTC()
	return s.db.WithContext(ctx).Save(&user).Error
}

func (s *AuthService) GetCurrentUser(ctx context.Context, userID uint) (model.AIUser, error) {
	var user model.AIUser
	err := s.db.WithContext(ctx).First(&user, userID).Error
	return user, err
}

// ValidateToken parses and validates a token, returning the payload.
func (s *AuthService) ValidateToken(token string) (*tokenPayload, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding")
	}

	// Verify signature
	expectedSig := s.computeHMAC(payloadBytes)
	actualSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token signature encoding")
	}
	if !hmac.Equal(expectedSig, actualSig) {
		return nil, fmt.Errorf("invalid token signature")
	}

	var payload tokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid token payload")
	}

	if time.Now().Unix() > payload.Exp {
		return nil, fmt.Errorf("token expired")
	}

	var user model.AIUser
	if err := s.db.First(&user, payload.UserID).Error; err != nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.Enabled {
		return nil, fmt.Errorf("user disabled")
	}
	payload.Username = user.Username
	payload.Role = user.Role

	return &payload, nil
}

func (s *AuthService) signToken(payload tokenPayload) (string, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sig := s.computeHMAC(payloadBytes)
	token := base64.RawURLEncoding.EncodeToString(payloadBytes) + "." + base64.RawURLEncoding.EncodeToString(sig)
	return token, nil
}

func (s *AuthService) computeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(data)
	return mac.Sum(nil)
}
