package handler

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/service"
)

type OAuthHandlers struct {
	oauth   *service.OAuthService
	session *service.SessionService
	baseURL string
}

func NewOAuthHandlers(oauth *service.OAuthService, session *service.SessionService, baseURL string) *OAuthHandlers {
	return &OAuthHandlers{
		oauth:   oauth,
		session: session,
		baseURL: baseURL,
	}
}

// GET /auth/{provider}
func (h *OAuthHandlers) Initiate(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	url, err := h.oauth.Initiate(r.Context(), provider)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": url})
}

// POST /auth/link/{provider} — requires auth
func (h *OAuthHandlers) InitiateLink(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, domain.NewError("unauthorized", "Authentication required", 401))
		return
	}

	provider := r.PathValue("provider")
	url, err := h.oauth.InitiateLink(r.Context(), provider, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": url})
}

// GET /auth/{provider}/callback
func (h *OAuthHandlers) Callback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Redirect(w, r, h.baseURL+"/auth/callback?error=invalid_request&provider="+provider, http.StatusFound)
		return
	}

	sessionToken, refreshToken, _, err := h.oauth.Callback(r.Context(), provider, code, state)
	if err != nil {
		http.Redirect(w, r, h.baseURL+"/auth/callback?error="+err.Code+"&provider="+provider, http.StatusFound)
		return
	}

	setSessionCookie(w, h.session, sessionToken)
	setRefreshCookie(w, h.session, refreshToken)
	http.Redirect(w, r, h.baseURL+"/auth/callback", http.StatusFound)
}

// POST /auth/unlink/{provider} — requires auth
func (h *OAuthHandlers) Unlink(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, domain.NewError("unauthorized", "Authentication required", 401))
		return
	}

	provider := r.PathValue("provider")
	if err := h.oauth.Unlink(r.Context(), user.ID, provider); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Provider unlinked"})
}

// GET /auth/providers — requires auth
func (h *OAuthHandlers) ListConnected(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, domain.NewError("unauthorized", "Authentication required", 401))
		return
	}

	accounts, err := h.oauth.ListConnected(r.Context(), user.ID)
	if err != nil {
		writeError(w, err)
		return
	}

	// Return only safe fields — no access/refresh tokens
	type safeAccount struct {
		Provider      string `json:"provider"`
		ProviderEmail string `json:"email"`
		ProviderName  string `json:"name"`
		AvatarURL     string `json:"avatar_url"`
		CreatedAt     string `json:"created_at"`
	}
	safe := make([]safeAccount, len(accounts))
	for i, a := range accounts {
		safe[i] = safeAccount{
			Provider:      a.Provider,
			ProviderEmail: a.ProviderEmail,
			ProviderName:  a.ProviderName,
			AvatarURL:     a.AvatarURL,
			CreatedAt:     a.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"providers": safe})
}
