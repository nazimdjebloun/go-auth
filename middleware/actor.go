package middleware

import (
	"context"

	"github.com/nazimdjebloun/go-auth/api"
)

// ActorFromContext projects the identity established by authentication into a
// transport-neutral actor. Call it after Auth.RequireAuth or Auth.Protect.
// Missing, empty or mismatched user/session identity returns the zero actor and
// false. This is a context accessor, not credential validation: public context
// setters are trusted backend plumbing and must never accept client identity.
// Services must check current access before each operation, even with an actor
// retained from an earlier successful request.
func ActorFromContext(ctx context.Context) (api.Actor, bool) {
	user := GetUserFromContext(ctx)
	session := GetSessionFromContext(ctx)
	if user == nil || session == nil || user.ID == "" || session.ID == "" || session.UserID != user.ID {
		return api.Actor{}, false
	}
	return api.Actor{UserID: user.ID, SessionID: session.ID}, true
}
