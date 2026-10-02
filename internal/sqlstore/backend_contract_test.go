package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestBackendTokenClaimConcurrentAcrossPools(t *testing.T) {
	db := backendDB(t)
	user := backendUser(t, db)
	id := uuid.NewString()
	now := time.Now().UTC().Truncate(time.Second)
	if err := NewTokenRepository(db).Create(t.Context(), &domain.VerificationToken{ID: id, UserID: &user, Email: user + "@example.com", TokenHash: "one-time-hash", Type: domain.TokenTwoFactor, ExpiresAt: now.Add(time.Hour), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	other := testdb.SecondPool(t, db.DB)
	repos := []*TokenRepository{NewTokenRepository(db), NewTokenRepository(NewDB(other, db.Driver()))}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	start := make(chan struct{})
	type result struct {
		claimed bool
		err     error
	}
	results := make(chan result, 16)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			<-start
			claimed, err := repos[i%2].ConsumeIfValidUnderCap(ctx, port.ConsumeTokenInput{ID: id, UserID: user, TokenHash: "one-time-hash", Type: domain.TokenTwoFactor, UsedAt: now}, 5)
			results <- result{claimed, err}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.claimed {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("claim winners=%d want 1", winners)
	}
}

func TestBackendCredentialCompareAndSwap(t *testing.T) {
	db := backendDB(t)
	id := backendUser(t, db)
	ctx := t.Context()
	old, current, next := "old-hash", "current-hash", "next-hash"
	if _, err := db.ExecContext(ctx, "UPDATE users SET password_hash=$1 WHERE id=$2", old, id); err != nil {
		t.Fatal(err)
	}
	repo := NewUserRepository(db)
	v1, v2 := uint32(1), uint32(2)
	changed, err := repo.UpdatePasswordHash(ctx, id, old, nil, current, &v1, time.Now().UTC())
	if err != nil || !changed {
		t.Fatalf("first replacement=%v %v", changed, err)
	}
	for _, tc := range []struct {
		name, expectedHash string
		expectedVersion    *uint32
	}{{"stale hash", old, &v1}, {"stale version", current, nil}} {
		t.Run(tc.name, func(t *testing.T) {
			changed, err := repo.UpdatePasswordHash(ctx, id, tc.expectedHash, tc.expectedVersion, next, &v2, time.Now().UTC())
			if err != nil || changed {
				t.Fatalf("stale replacement=%v %v", changed, err)
			}
		})
	}
	user, err := repo.GetByID(ctx, id)
	if err != nil || user.PasswordHash == nil || *user.PasswordHash != current || user.PasswordPepperVersion == nil || *user.PasswordPepperVersion != v1 {
		t.Fatalf("credential overwritten: %+v %v", user, err)
	}
}

func TestBackendSessionAssuranceRoundTrip(t *testing.T) {
	db := backendDB(t)
	user := backendUser(t, db)
	repo := NewSessionRepository(db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, verified := range []bool{false, true} {
		t.Run(fmt.Sprint(verified), func(t *testing.T) {
			id := uuid.NewString()
			s := &domain.Session{ID: id, UserID: user, TokenHash: id, RefreshTokenHash: id + "refresh", ExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(2 * time.Hour), CreatedAt: now, LastActiveAt: now}
			if verified {
				s.TwoFactorVerifiedAt = &now
			}
			if err := repo.Create(t.Context(), s); err != nil {
				t.Fatal(err)
			}
			got, err := repo.GetByTokenHash(t.Context(), id)
			if err != nil || got == nil {
				t.Fatalf("read=%+v %v", got, err)
			}
			if (got.TwoFactorVerifiedAt != nil) != verified {
				t.Fatal("assurance nullability changed")
			}
			if verified && !got.TwoFactorVerifiedAt.Equal(now) {
				t.Fatalf("assurance time=%v want %v", got.TwoFactorVerifiedAt, now)
			}
		})
	}
}

func TestBackendTransactionRollbackPanicAndSavepoint(t *testing.T) {
	for _, mode := range []string{"error", "panic", "savepoint"} {
		t.Run(mode, func(t *testing.T) {
			db := backendDB(t)
			sentinel := errors.New("injected rollback")
			id := uuid.NewString()
			insert := func(ctx context.Context, key string) error {
				return NewRecordRepository(db).Insert(ctx, audit.Event{ID: key, Type: audit.EventLoginSuccess, Severity: audit.SeverityInfo, Success: true, CreatedAt: time.Now().UTC()})
			}
			func() {
				if mode == "panic" {
					defer func() {
						if recover() != sentinel {
							t.Error("panic was not propagated")
						}
					}()
				}
				err := db.WithTx(t.Context(), func(ctx context.Context) error {
					if err := insert(ctx, id); err != nil {
						return err
					}
					if mode == "panic" {
						panic(sentinel)
					}
					if mode == "error" {
						return sentinel
					}
					if err := db.Savepoint(ctx, "duplicate_audit", func(ctx context.Context) error { return insert(ctx, id) }); err == nil {
						return errors.New("duplicate insert succeeded")
					}
					return insert(ctx, uuid.NewString())
				})
				if mode == "error" && !errors.Is(err, sentinel) {
					t.Fatalf("rollback=%v", err)
				}
				if mode == "savepoint" && err != nil {
					t.Fatal(err)
				}
			}()
			if inUse := db.Stats().InUse; inUse != 0 {
				t.Fatalf("transaction retained %d pooled connections", inUse)
			}
			var n int
			if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM audit_log").Scan(&n); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "savepoint" {
				want = 2
			}
			if n != want {
				t.Fatalf("rows=%d want %d", n, want)
			}
			if err := db.PingContext(t.Context()); err != nil {
				t.Fatal("transaction leaked its connection", err)
			}
		})
	}
}

func TestBackendAuthenticationLockCancellation(t *testing.T) {
	db := backendDB(t)
	user := backendUser(t, db)
	other := NewDB(testdb.SecondPool(t, db.DB), db.Driver())
	if db.Driver() == "sqlite" {
		// SQLite checks cancellation between busy-handler retries. Bound that
		// retry on the single competing connection as well as the context.
		other.SetMaxOpenConns(1)
		if _, err := other.ExecContext(t.Context(), "PRAGMA busy_timeout=250"); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	locked, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	unlock := func() { once.Do(func() { close(release) }) }
	defer func() {
		unlock()
		cancel()
	}()
	go func() {
		finished <- db.WithTx(ctx, func(ctx context.Context) error {
			if _, err := NewUserRepository(db).GetByIDForUpdate(ctx, user); err != nil {
				return err
			}
			close(locked)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-locked:
	case err := <-finished:
		t.Fatalf("lock failed: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	blocked, stop := context.WithTimeout(ctx, 150*time.Millisecond)
	started := time.Now()
	err := other.WithTx(blocked, func(ctx context.Context) error {
		_, err := NewUserRepository(other).GetByIDForUpdate(ctx, user)
		return err
	})
	elapsed := time.Since(started)
	deadlineReached := errors.Is(blocked.Err(), context.DeadlineExceeded)
	stop()
	if err == nil {
		t.Error("second connection bypassed user lock")
	}
	var sqliteCode interface{ Code() int }
	canceled := errors.Is(err, context.DeadlineExceeded) ||
		(db.Driver() == "sqlite" && deadlineReached && errors.As(err, &sqliteCode) && sqliteCode.Code() == 5)
	if !canceled || elapsed > 2*time.Second {
		t.Errorf("blocked operation=%v after %v; want deadline cancellation within 2s", err, elapsed)
	}
	unlock()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := other.WithTx(ctx, func(ctx context.Context) error {
		_, err := NewUserRepository(other).GetByIDForUpdate(ctx, user)
		return err
	}); err != nil {
		t.Fatalf("lock leaked after cancellation: %v", err)
	}
}

func TestBackendMaintenanceBatchBoundaries(t *testing.T) {
	db := backendDB(t)
	user := backendUser(t, db)
	repo := NewTokenRepository(db)
	now := time.Now().UTC().Truncate(time.Second)
	for i := range 5 {
		id := uuid.NewString()
		expiry := now.Add(-time.Hour)
		if i == 4 {
			expiry = now.Add(time.Hour)
		}
		if err := repo.Create(t.Context(), &domain.VerificationToken{ID: id, UserID: &user, Email: "maintenance@example.com", TokenHash: id, Type: domain.TokenResetPass, ExpiresAt: expiry, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []int{2, 2, 0} {
		got, err := repo.DeleteExpiredBatch(t.Context(), now, 2)
		if err != nil || got != want {
			t.Fatalf("batch=%d %v want %d", got, err, want)
		}
	}
	if _, err := repo.DeleteExpiredBatch(t.Context(), now, 0); err == nil {
		t.Fatal("zero batch limit accepted")
	}
	var n int
	if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM verification_tokens").Scan(&n); err != nil || n != 1 {
		t.Fatalf("live token deleted: %d %v", n, err)
	}
}

func TestBackendUserPaginationAndDailyCounts(t *testing.T) {
	db := backendDB(t)
	repo := NewUserRepository(db)
	const size, pageSize = 512, 31
	base := time.Date(2026, time.October, 1, 23, 56, 0, 0, time.UTC)
	ids := make([]string, size)
	if err := db.WithTx(t.Context(), func(ctx context.Context) error {
		for i := range size {
			ids[i] = uuid.NewString()
			created := base.Add(time.Duration(i) * time.Second)
			if err := repo.Create(ctx, &domain.User{
				ID: ids[i], Email: fmt.Sprintf("user-%04d@example.com", i),
				Name: fmt.Sprintf("user-%04d 名 😀", i), Role: domain.RoleUser,
				IsVerified: i%3 == 0, CreatedAt: created, UpdatedAt: created,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < size+pageSize; offset += pageSize {
		page, err := repo.List(t.Context(), port.UserFilter{OrderBy: api.UserSortCreatedAt, OrderDirection: api.SortAscending, Offset: offset, Limit: pageSize})
		if err != nil {
			t.Fatal(err)
		}
		want := min(pageSize, max(0, size-offset))
		if len(page) != want {
			t.Fatalf("offset %d: page length=%d want %d", offset, len(page), want)
		}
		for j, user := range page {
			if user.ID != ids[offset+j] || user.Name != fmt.Sprintf("user-%04d 名 😀", offset+j) || user.IsVerified != ((offset+j)%3 == 0) {
				t.Fatalf("offset %d row %d: order or Unicode/boolean roundtrip changed: %+v", offset, j, user)
			}
		}
	}
	verified := true
	search := "USER-0"
	filter := port.UserFilter{IsVerified: &verified, Search: &search, Offset: 400, Limit: 1}
	if count, err := repo.Count(t.Context(), filter); err != nil || count != (size+2)/3 {
		t.Fatalf("filtered count ignores pagination: count=%d err=%v", count, err)
	}
	days, err := repo.CountByDay(t.Context(), port.UserFilter{Limit: 1, Offset: 400})
	if err != nil || len(days) != 2 {
		t.Fatalf("daily counts=%v err=%v", days, err)
	}
	for i, want := range []int{240, size - 240} {
		date := time.Date(2026, time.October, 1+i, 0, 0, 0, 0, time.UTC)
		if days[i].Count != want || !days[i].Date.Equal(date) {
			t.Fatalf("day %d=%+v want %v count %d", i, days[i], date, want)
		}
	}
	testdb.AssertForeignKeyIntegrity(t, db.DB)
}
