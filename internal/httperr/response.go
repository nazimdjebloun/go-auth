package httperr

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
)

// Write emits the common error envelope. The status is explicit because an
// authentication boundary may intentionally conceal a more specific failure.
func Write(w http.ResponseWriter, status int, code, message string, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(domain.AuthError{Code: code, Message: message}); err != nil {
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("failed to encode JSON error response", "err", err, "status", status)
	}
}
