package service

import (
	"context"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func TestAdminCreateUserAuditIdentifiesActorAndTarget(t *testing.T) {
	svc, actorID := newTestAdminService(testutil.NewMockUserRepo(), testutil.NewMockSessionRepo(), &testutil.MockHasher{})
	publisher := testutil.NewMockAuditPublisher()
	svc.audit = publisher
	user, err := svc.CreateUser(context.Background(), api.CreateUserInput{
		ActorID: actorID, Email: "created@example.com", Name: "Created User", Password: "SecurePass123!",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(publisher.Events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(publisher.Events))
	}
	event := publisher.Events[0]
	if event.Type != audit.EventAdminUserCreated || event.ActorID == nil || *event.ActorID != actorID ||
		event.TargetUserID == nil || *event.TargetUserID != user.ID {
		t.Fatalf("creation event must identify the authorized actor and created user: %#v", event)
	}
}
