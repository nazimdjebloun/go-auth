package middleware

import (
	"context"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

func TestActorFromContext(t *testing.T) {
	for _, test := range []struct {
		name    string
		user    *domain.User
		session *domain.Session
		wantOK  bool
	}{
		{name: "missing identity"},
		{name: "missing session", user: &domain.User{ID: "user"}},
		{name: "missing user", session: &domain.Session{ID: "session", UserID: "user"}},
		{name: "empty user ID", user: &domain.User{}, session: &domain.Session{ID: "session"}},
		{name: "empty session ID", user: &domain.User{ID: "user"}, session: &domain.Session{UserID: "user"}},
		{name: "mismatched identity", user: &domain.User{ID: "user"}, session: &domain.Session{ID: "session", UserID: "other"}},
		{name: "matching identity", user: &domain.User{ID: "user"}, session: &domain.Session{ID: "session", UserID: "user"}, wantOK: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := ContextWithSession(ContextWithUser(context.Background(), test.user), test.session)
			actor, ok := ActorFromContext(ctx)
			if ok != test.wantOK {
				t.Fatalf("ok=%t want %t", ok, test.wantOK)
			}
			if !ok && actor != (api.Actor{}) {
				t.Fatal("incomplete identity returned a partial actor")
			}
			if ok && actor != (api.Actor{UserID: "user", SessionID: "session"}) {
				t.Fatalf("wrong actor: %+v", actor)
			}
		})
	}
}
