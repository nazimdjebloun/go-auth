package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

type unavailableLoginUsers struct{ *testutil.MockUserRepo }

func (*unavailableLoginUsers) GetByEmail(context.Context, string) (*domain.User, error) {
	return nil, errors.New("private backend connection detail")
}

func TestLoginBackendFailureReturnsGenericInternalError(t *testing.T) {
	svc := service.NewAuthService(&unavailableLoginUsers{testutil.NewMockUserRepo()}, nil, nil, nil, nil, nil, service.Config{}, nil, nil, nil)
	h := New(Deps{Auth: svc})
	r := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"email":"user@example.com","password":"WrongPassword1!"}`))
	w := httptest.NewRecorder()
	h.Login(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body)
	}
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["error"] != "internal_error" || got["message"] != domain.ErrInternal.Message || len(got) != 2 {
		t.Fatalf("unexpected error envelope: %v", got)
	}
}
