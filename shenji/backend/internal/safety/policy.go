package safety

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

type SafePolicy struct {
	AuthorizationLevel         int      `json:"authorizationLevel"`
	AllowedScopes              []string `json:"allowedScopes"`
	AllowChainExploration      bool     `json:"allowChainExploration"`
	AllowReadOnlyCommands      bool     `json:"allowReadOnlyCommands"`
	AllowEvidenceProofCommands bool     `json:"allowEvidenceProofCommands"`
	AllowSandboxVerification   bool     `json:"allowSandboxVerification"`
	NetworkPolicy              string   `json:"networkPolicy"`
	Mode                       string   `json:"mode"` // enterprise / lab / manual_approval
}

// Policy modes per prompt section 7.1
const (
	PolicyModeEnterprise     = "enterprise"      // Default. Only low-risk proof allowed.
	PolicyModeLab            = "lab"             // Lab/CTF mode. Allow flag read, proof command, limited marker write.
	PolicyModeManualApproval = "manual_approval" // High-risk actions require human confirmation.
)

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

var (
	ErrOutOfScope      = errors.New("target is outside authorized scope")
	ErrBlockedPayload  = errors.New("payload is blocked by safe policy")
	ErrBlockedCommand  = errors.New("command is blocked by safe policy")
	ErrInvalidTarget   = errors.New("invalid target")
	dangerousFragments = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(^|\s)(rm|del|format|mkfs|shutdown|reboot|halt|poweroff)\b`),
		regexp.MustCompile(`(?i)\brm\s+-[^\n]*r[^\n]*f\b`),
		regexp.MustCompile(`(?i)(^|\s)(kill|pkill|killall)\b`),
		regexp.MustCompile(`(?i)\b(dd)\b.*\b(of=|if=)`),
		regexp.MustCompile(`(?i)\b(crontab|systemctl|launchctl|schtasks|service)\b`),
		regexp.MustCompile(`(?i)\b(nohup|setsid|disown)\b`),
		regexp.MustCompile(`(?i)\b(useradd|adduser|net\s+user)\b`),
		regexp.MustCompile(`(?i)(authorized_keys|/etc/passwd|/etc/shadow)`),
		regexp.MustCompile(`(?i)(nc|ncat|bash|sh|zsh|powershell|pwsh)\s+.*(-e|/dev/tcp)`),
		regexp.MustCompile(`(?i)\bwget\b`),
		regexp.MustCompile(`(?i)\b(curl|wget)\b.*\|\s*(sh|bash|zsh)`),
		regexp.MustCompile(`(?i)\bcurl\b.*(-o|--output|>)\s*\S+.*(&&|;)\s*(chmod\s+\+x|sh|bash|zsh|python|perl|ruby)`),
		regexp.MustCompile(`(?i)\bchmod\s+\+x\b`),
		regexp.MustCompile(`(?i)(history\s+-c|/var/log|truncate\s+-s\s+0|:>\s*[^\s]*log|:\s*>\s*[^\s]*log)`),
		regexp.MustCompile(`(?i)(iptables|ip6tables|pfctl)\b`),
		regexp.MustCompile(`(?i)(: \(\)\s*\{|:\(\)\s*\{|fork\s*bomb|yes\s*>|while\s+true\s*;)`),
		regexp.MustCompile(`(?i)\b(eval|assert|Runtime\.getRuntime|ProcessBuilder)\b.*(cmd|command|exec)`),
	}
)

func DefaultPolicy(scopes []string, level int) SafePolicy {
	return SafePolicy{
		AuthorizationLevel:         level,
		AllowedScopes:              scopes,
		AllowChainExploration:      true,
		AllowReadOnlyCommands:      true,
		AllowEvidenceProofCommands: true,
		AllowSandboxVerification:   true,
		NetworkPolicy:              "authorized-scope-only",
		Mode:                       PolicyModeEnterprise,
	}
}

func (p SafePolicy) ValidateTarget(ctx context.Context, rawTarget string) error {
	_ = ctx
	host, err := hostFromTarget(rawTarget)
	if err != nil {
		return err
	}
	if len(p.AllowedScopes) == 0 {
		if isDefaultBlockedHost(host) {
			return fmt.Errorf("%w: %s is blocked unless explicitly authorized", ErrOutOfScope, host)
		}
		return nil
	}
	for _, scope := range p.AllowedScopes {
		if matchesScope(host, strings.TrimSpace(scope)) {
			return nil
		}
	}
	if isDefaultBlockedHost(host) {
		return fmt.Errorf("%w: %s is blocked unless explicitly authorized", ErrOutOfScope, host)
	}
	return fmt.Errorf("%w: %s", ErrOutOfScope, host)
}

func (p SafePolicy) ValidateCommand(ctx context.Context, command string) error {
	_ = ctx
	normalized := strings.TrimSpace(command)
	if normalized == "" {
		return nil
	}
	for _, fragment := range dangerousFragments {
		if fragment.MatchString(normalized) {
			return fmt.Errorf("%w: destructive or persistent command fragment detected", ErrBlockedCommand)
		}
	}
	if p.AllowEvidenceProofCommands || p.AllowReadOnlyCommands || p.AuthorizationLevel >= 0 {
		return nil
	}
	return fmt.Errorf("%w: evidence proof commands are disabled", ErrBlockedCommand)
}

func (p SafePolicy) ValidatePayload(ctx context.Context, payload string) error {
	_ = ctx
	normalized := strings.TrimSpace(payload)
	if normalized == "" {
		return nil
	}
	for _, fragment := range dangerousFragments {
		if fragment.MatchString(normalized) {
			return fmt.Errorf("%w: destructive or persistent payload detected", ErrBlockedPayload)
		}
	}
	if strings.Contains(strings.ToLower(normalized), "webshell") || strings.Contains(strings.ToLower(normalized), "reverse shell") {
		return fmt.Errorf("%w: backdoor-style payloads are not allowed", ErrBlockedPayload)
	}
	return nil
}

func (p SafePolicy) DecideCommand(ctx context.Context, command string) Decision {
	if err := p.ValidateCommand(ctx, command); err != nil {
		return Decision{Allowed: false, Reason: err.Error()}
	}
	return Decision{Allowed: true, Reason: "allowed by non-destructive evidence proof policy"}
}

func hostFromTarget(rawTarget string) (string, error) {
	if rawTarget == "" {
		return "", ErrInvalidTarget
	}
	parsed, err := url.Parse(rawTarget)
	if err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname()), nil
	}
	host := rawTarget
	if strings.Contains(rawTarget, "/") {
		return "", fmt.Errorf("%w: %s", ErrInvalidTarget, rawTarget)
	}
	if strings.Contains(rawTarget, ":") {
		if h, _, splitErr := net.SplitHostPort(rawTarget); splitErr == nil {
			host = h
		}
	}
	return strings.ToLower(strings.Trim(host, "[] ")), nil
}

func isDefaultBlockedHost(host string) bool {
	blocked := map[string]bool{
		"169.254.169.254": true,
		"127.0.0.1":       true,
		"localhost":       true,
		"0.0.0.0":         true,
		"::1":             true,
	}
	if blocked[host] {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}
	for _, raw := range privateCIDRs {
		_, cidr, _ := net.ParseCIDR(raw)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func matchesScope(host string, scope string) bool {
	if scope == "" {
		return false
	}
	scopeHost, err := hostFromTarget(scope)
	if err == nil {
		scope = scopeHost
	}
	if _, cidr, err := net.ParseCIDR(scope); err == nil {
		ip := net.ParseIP(host)
		return ip != nil && cidr.Contains(ip)
	}
	if strings.EqualFold(host, scope) {
		return true
	}
	return strings.HasSuffix(host, "."+strings.TrimPrefix(scope, "."))
}
