package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

var sensitiveLine = regexp.MustCompile(`(?i)(authorization|cookie|token|password|secret|api[-_ ]?key|session|bearer)(\s*[:=]\s*)([^\s,"\']+)`)

func RedactSensitive(raw string) string {
	return sensitiveLine.ReplaceAllStringFunc(raw, func(match string) string {
		parts := sensitiveLine.FindStringSubmatch(match)
		if len(parts) != 4 {
			return "[REDACTED]"
		}
		value := parts[3]
		sum := sha256.Sum256([]byte(value))
		prefix := ""
		suffix := ""
		if len(value) >= 4 {
			prefix = value[:2]
			suffix = value[len(value)-2:]
		}
		return fmt.Sprintf("%s%s%s...[redacted len=%d sha256=%s]...%s", parts[1], parts[2], prefix, len(value), hex.EncodeToString(sum[:])[:12], suffix)
	})
}
