package goauth

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/httperr"
)

// ErrHTTPDisabled reports browser HTTP use on a service-only Auth instance.
// Mount and cookie helpers return it; HTTP middleware rejects requests with
// its http_disabled code and status 503. Handler lookup returns nil, false.
var ErrHTTPDisabled = domain.ErrHTTPDisabled

func (a *Auth) denyHTTP() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httperr.Write(w, http.StatusServiceUnavailable,
			ErrHTTPDisabled.Code, ErrHTTPDisabled.Message, a.cfg.logger)
	})
}

// denyHTTPMiddleware adapts the rejection handler to middleware factories.
func (a *Auth) denyHTTPMiddleware(_ http.Handler) http.Handler {
	return a.denyHTTP()
}
