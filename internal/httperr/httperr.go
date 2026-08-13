// Package httperr maps domain.AuthError codes to HTTP status codes. It is
// the one place that mapping lives — domain stays transport-agnostic (usable
// from Auth.Register/Auth.Login directly, with no HTTP concept at all), while
// both internal/handler and middleware need the same code->status contract
// for identical responses to identical failures.
package httperr

import "net/http"

var byCode = map[string]int{
	"internal_error":               http.StatusInternalServerError,
	"email_already_exists":         http.StatusConflict,
	"invalid_credentials":          http.StatusUnauthorized,
	"user_banned":                  http.StatusForbidden,
	"email_not_verified":           http.StatusForbidden,
	"weak_password":                http.StatusBadRequest,
	"invalid_email":                http.StatusBadRequest,
	"user_not_found":               http.StatusNotFound,
	"forbidden":                    http.StatusForbidden,
	"reset_token_expired":          http.StatusGone,
	"reset_token_invalid":          http.StatusBadRequest,
	"reset_token_already_used":     http.StatusGone,
	"invite_not_found":             http.StatusNotFound,
	"invite_expired":               http.StatusGone,
	"invite_already_used":          http.StatusGone,
	"invite_revoked":               http.StatusForbidden,
	"rate_limit_exceeded":          http.StatusTooManyRequests,
	"account_already_exists":       http.StatusConflict,
	"session_not_found":            http.StatusNotFound,
	"session_expired":              http.StatusUnauthorized,
	"session_revoked":              http.StatusUnauthorized,
	"invalid_refresh_token":        http.StatusUnauthorized,
	"refresh_expired":              http.StatusUnauthorized,
	"token_already_rotated":        http.StatusConflict,
	"max_lifetime_exceeded":        http.StatusUnauthorized,
	"provider_not_found":           http.StatusNotFound,
	"provider_already_linked":      http.StatusConflict,
	"provider_not_linked":          http.StatusNotFound,
	"cannot_unlink_last_provider":  http.StatusBadRequest,
	"delete_code_invalid":          http.StatusBadRequest,
	"delete_code_expired":          http.StatusGone,
	"delete_code_already_used":     http.StatusGone,
	"password_required":            http.StatusBadRequest,
	"org_not_found":                http.StatusNotFound,
	"org_slug_exists":              http.StatusConflict,
	"org_slug_reserved":            http.StatusBadRequest,
	"org_member_not_found":         http.StatusNotFound,
	"org_member_exists":            http.StatusConflict,
	"cannot_remove_last_owner":     http.StatusBadRequest,
	"org_limit_reached":            http.StatusBadRequest,
	"org_member_limit_reached":     http.StatusBadRequest,
	"org_forbidden":                http.StatusForbidden,
	"org_invite_expired":           http.StatusBadRequest,
	"org_invite_email_mismatch":    http.StatusBadRequest,
	"org_metadata_too_large":       http.StatusBadRequest,
	"method_disabled":              http.StatusMethodNotAllowed,
	"two_factor_code_invalid":      http.StatusBadRequest,
	"two_factor_code_expired":      http.StatusGone,
	"two_factor_code_already_used": http.StatusGone,
	"two_factor_already_enforced":  http.StatusConflict,
	"two_factor_password_required": http.StatusBadRequest,

	// Ad hoc codes constructed inline at their one or few call sites in
	// service/ and internal/handler/, rather than as domain.Err* sentinels.
	"already_banned":       http.StatusBadRequest,
	"last_admin":           http.StatusBadRequest,
	"not_banned":           http.StatusBadRequest,
	"invalid_role":         http.StatusBadRequest,
	"name_required":        http.StatusBadRequest,
	"validation_error":     http.StatusBadRequest,
	"wrong_password":       http.StatusBadRequest,
	"password_account":     http.StatusBadRequest,
	"email_not_configured": http.StatusInternalServerError,
	"email_failed":         http.StatusInternalServerError,
	"invalid_slug":         http.StatusBadRequest,
	"invalid_name":         http.StatusBadRequest,
	"invalid_state":        http.StatusBadRequest,
	"state_used":           http.StatusBadRequest,
	"state_expired":        http.StatusBadRequest,
	"provider_error":       http.StatusBadGateway,
	"already_linked":       http.StatusConflict,
	"already_set":          http.StatusBadRequest,
	"invalid_code":         http.StatusBadRequest,
	"code_used":            http.StatusBadRequest,
	"no_password":          http.StatusBadRequest,
	"password_mismatch":    http.StatusBadRequest,
	"invalid_refresh":      http.StatusUnauthorized,
	"invalid_input":        http.StatusBadRequest,
	"missing_token":        http.StatusBadRequest,
	"unauthorized":         http.StatusUnauthorized,
	"code_invalid":         http.StatusBadRequest,
	"code_already_used":    http.StatusGone,
	"code_expired":         http.StatusGone,
	"already_verified":     http.StatusBadRequest,

	// Deliberately vague, non-enumerable responses: these return 200 so a
	// caller probing for account/challenge existence can't distinguish
	// "not found" from "found, and an email/code was sent" by status code
	// alone — see service/verification.go and service/twofactor.go.
	"email_not_found":     http.StatusOK,
	"challenge_not_found": http.StatusOK,
}

// StatusFor returns the HTTP status the built-in handlers and middleware
// respond with for a domain.AuthError code. A code with no entry falls back
// to 500 — fail-closed, so a new error code that forgets to register here
// surfaces as a generic server error instead of a wrong 2xx/4xx.
func StatusFor(code string) int {
	if status, ok := byCode[code]; ok {
		return status
	}
	return http.StatusInternalServerError
}
