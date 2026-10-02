package sqlstore

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
)

func TestBackendProviderIdentityIsExact(t *testing.T) {
	db := backendDB(t)
	user := backendUser(t, db)
	repo := NewProviderAccountRepository(db)
	now := time.Now().UTC()
	subjects := []string{"SubjectABC", "subjectabc", "SubjectABC ", "SubjectÁBC", "SubjectA\u0301BC"}
	for _, subject := range subjects {
		if err := repo.Create(t.Context(), &domain.ProviderAccount{ID: uuid.NewString(), UserID: user, Provider: "custom", ProviderUserID: subject, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("distinct subject %q must coexist: %v", subject, err)
		}
	}
	for _, subject := range subjects {
		got, err := repo.GetByProvider(t.Context(), "custom", subject)
		if err != nil || got == nil || got.ProviderUserID != subject {
			t.Fatalf("subject lookup=%+v %v want %q", got, err, subject)
		}
	}
	got, err := repo.GetByProvider(t.Context(), "custom", "SUBJECTABC")
	if err != nil || got != nil {
		t.Fatalf("case-folded identity matched: %+v %v", got, err)
	}
	got, err = repo.GetByProvider(t.Context(), "CUSTOM", "SubjectABC")
	if err != nil || got != nil {
		t.Fatalf("case-folded provider matched: %+v %v", got, err)
	}
}
