package sqlstore

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type snapshotMemory struct {
	mu        sync.Mutex
	values    map[string][]byte
	gets      int
	fail      bool
	beforePut func()
}

func (m *snapshotMemory) Get(_ context.Context, k string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	if m.fail {
		return nil, errors.New("injected cache outage")
	}
	return append([]byte(nil), m.values[k]...), nil
}
func (m *snapshotMemory) Put(_ context.Context, k string, v []byte, _ time.Duration) error {
	if m.beforePut != nil {
		m.beforePut()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.values == nil {
		m.values = map[string][]byte{}
	}
	if m.values[k] == nil {
		m.values[k] = append([]byte(nil), v...)
	}
	return nil
}

func TestSnapshotLateFillCannotReviveConsumedToken(t *testing.T) {
	db := backendDB(t)
	r := NewTokenRepository(db)
	c, m := testSnapshots(t)
	r.WithSnapshotCache(c)
	now := time.Now().UTC()
	user := backendUser(t, db)
	tok := &domain.VerificationToken{ID: uuid.NewString(), UserID: &user, Email: "late-fill@example.test", TokenHash: uuid.NewString(), Type: domain.TokenSetPass, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if e := r.Create(t.Context(), tok); e != nil {
		t.Fatal(e)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	m.beforePut = func() { once.Do(func() { close(entered); <-resume }) }
	done := make(chan error, 1)
	go func() { _, e := r.GetByID(t.Context(), tok.ID); done <- e }()
	<-entered
	claimed, e := r.MarkUsedIfUnused(t.Context(), tok.ID)
	release()
	if readErr := <-done; readErr != nil {
		t.Fatal(readErr)
	}
	if e != nil || !claimed {
		t.Fatal(claimed, e)
	}
	current, e := r.GetByID(t.Context(), tok.ID)
	if e != nil || current == nil || current.UsedAt == nil {
		t.Fatal("late cache fill revived consumed proof", e)
	}
}
func testSnapshots(t *testing.T) (*SnapshotCache, *snapshotMemory) {
	t.Helper()
	m := &snapshotMemory{}
	c, e := NewSnapshotCache(m, bytes.Repeat([]byte{7}, 32), time.Minute, 256*1024)
	if e != nil {
		t.Fatal(e)
	}
	return c, m
}
func snapshotSessionFixture(t *testing.T, db *DB, r *SessionRepository) *domain.Session {
	t.Helper()
	now := time.Now().UTC()
	s := &domain.Session{ID: uuid.NewString(), UserID: backendUser(t, db), TokenHash: uuid.NewString(), RefreshTokenHash: uuid.NewString(), CreatedAt: now, LastActiveAt: now, ExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(time.Hour), TwoFactorVerifiedAt: &now}
	if e := r.Create(t.Context(), s); e != nil {
		t.Fatal(e)
	}
	return s
}
func cacheVersion(t *testing.T, db *DB, table, id string) string {
	t.Helper()
	var v string
	if e := db.QueryRowContext(t.Context(), "SELECT cache_version FROM "+table+" WHERE id=$1", id).Scan(&v); e != nil {
		t.Fatal(e)
	}
	return v
}

func TestSnapshotSessionRevocationAndRecreation(t *testing.T) {
	db := backendDB(t)
	r := NewSessionRepository(db)
	c, m := testSnapshots(t)
	r.WithSnapshotCache(c)
	s := snapshotSessionFixture(t, db, r)
	for range 2 {
		got, u, e := r.GetByTokenHashWithUser(t.Context(), s.TokenHash)
		if e != nil || got == nil || u == nil || got.TwoFactorVerifiedAt == nil || got.RefreshTokenHash != s.RefreshTokenHash {
			t.Fatalf("roundtrip: %+v %v", got, e)
		}
	}
	if c.Stats().Hits != 1 {
		t.Fatalf("expected warm hit: %+v", c.Stats())
	}
	for _, v := range m.values {
		if bytes.Contains(v, []byte(s.RefreshTokenHash)) {
			t.Fatal("snapshot exposes token hash")
		}
	}
	old := cacheVersion(t, db, "sessions", s.ID)
	if e := r.DeleteByID(t.Context(), s.ID); e != nil {
		t.Fatal(e)
	}
	if got, e := r.GetByTokenHash(t.Context(), s.TokenHash); e != nil || got != nil {
		t.Fatalf("revoked cached session: %+v %v", got, e)
	}
	s.TwoFactorVerifiedAt = nil
	if e := r.Create(t.Context(), s); e != nil {
		t.Fatal(e)
	}
	if old == cacheVersion(t, db, "sessions", s.ID) {
		t.Fatal("recreated row reused cache identity")
	}
	got, e := r.GetByTokenHash(t.Context(), s.TokenHash)
	if e != nil || got.TwoFactorVerifiedAt != nil {
		t.Fatalf("recreated session used old assurance: %+v %v", got, e)
	}
}

func TestSnapshotTransactionRollbackAndLegacy(t *testing.T) {
	db := backendDB(t)
	r := NewSessionRepository(db)
	c, m := testSnapshots(t)
	r.WithSnapshotCache(c)
	s := snapshotSessionFixture(t, db, r)
	if _, e := r.GetByTokenHash(t.Context(), s.TokenHash); e != nil {
		t.Fatal(e)
	}
	old := cacheVersion(t, db, "sessions", s.ID)
	before := m.gets
	rollback := errors.New("rollback")
	e := db.WithTx(t.Context(), func(ctx context.Context) error {
		if e := r.UpdateLastActiveAt(ctx, s.TokenHash); e != nil {
			return e
		}
		if _, e := r.GetByTokenHash(ctx, s.TokenHash); e != nil {
			return e
		}
		if m.gets != before {
			t.Fatal("transaction consulted Redis")
		}
		return rollback
	})
	if !errors.Is(e, rollback) || cacheVersion(t, db, "sessions", s.ID) != old {
		t.Fatal("rollback changed version", e)
	}
	if _, e = db.ExecContext(t.Context(), "UPDATE sessions SET cache_version='legacy' WHERE id=$1", s.ID); e != nil {
		t.Fatal(e)
	}
	before = m.gets
	if _, e = r.GetByTokenHash(t.Context(), s.TokenHash); e != nil {
		t.Fatal(e)
	}
	if m.gets != before {
		t.Fatal("legacy row consulted cache")
	}
	if e = r.UpdateLastActiveAt(t.Context(), s.TokenHash); e != nil {
		t.Fatal(e)
	}
	if cacheVersion(t, db, "sessions", s.ID) == "legacy" {
		t.Fatal("mutation kept legacy version")
	}
}

func TestSnapshotTokenClaimsResendsAndFallback(t *testing.T) {
	db := backendDB(t)
	r := NewTokenRepository(db)
	c, m := testSnapshots(t)
	r.WithSnapshotCache(c)
	user := backendUser(t, db)
	now := time.Now().UTC()
	verifier := "private-pkce-verifier"
	tok := &domain.VerificationToken{ID: uuid.NewString(), UserID: &user, Email: "proof@example.test", TokenHash: "old-hash", Type: domain.TokenTwoFactor, CreatedAt: now, ExpiresAt: now.Add(time.Hour), CodeVerifier: &verifier, ContextHash: "context", Attempts: 1}
	if e := r.Create(t.Context(), tok); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		v, e := r.GetByID(t.Context(), tok.ID)
		if e != nil || v == nil || v.TokenHash != tok.TokenHash || v.CodeVerifier == nil || *v.CodeVerifier != verifier || v.Attempts != 1 {
			t.Fatalf("token snapshot: %+v %v", v, e)
		}
	}
	old := cacheVersion(t, db, "verification_tokens", tok.ID)
	if ok, e := r.UpdateForResend(t.Context(), tok.ID, "new-hash", now.Add(time.Hour), now, 3, 5); e != nil || !ok {
		t.Fatal(ok, e)
	}
	if old == cacheVersion(t, db, "verification_tokens", tok.ID) {
		t.Fatal("resend did not invalidate")
	}
	v, e := r.GetByID(t.Context(), tok.ID)
	if e != nil || v.TokenHash != "new-hash" || v.Attempts != 1 || v.ResendCount != 1 {
		t.Fatalf("stale token: %+v %v", v, e)
	}
	old = cacheVersion(t, db, "verification_tokens", tok.ID)
	if ok, e := r.ConsumeIfValidUnderCap(t.Context(), port.ConsumeTokenInput{ID: tok.ID, TokenHash: "old-hash", UserID: user, Type: tok.Type, UsedAt: now}, 5); e != nil || ok {
		t.Fatal(ok, e)
	}
	if old != cacheVersion(t, db, "verification_tokens", tok.ID) {
		t.Fatal("failed claim changed version")
	}
	if ok, e := r.MarkUsedIfUnused(t.Context(), tok.ID); e != nil || !ok {
		t.Fatal(ok, e)
	}
	v, e = r.GetByID(t.Context(), tok.ID)
	if e != nil || v.UsedAt == nil {
		t.Fatal("used state hidden by cache", e)
	}
	m.fail = true
	if v, e = r.GetByID(t.Context(), tok.ID); e != nil || v.UsedAt == nil {
		t.Fatal("cache outage lost SQL truth", e)
	}
	if c.Stats().Errors == 0 {
		t.Fatal("cache outage was not observed")
	}
}

func TestSnapshotRejectsSubstitutionAndCorruption(t *testing.T) {
	c, m := testSnapshots(t)
	ctx := t.Context()
	writeSnapshot(ctx, c, "token", "one", "v1", map[string]string{"value": "secret"})
	key := snapshotKey("token", "one", "v1")
	raw := append([]byte(nil), m.values[key]...)
	m.values[snapshotKey("token", "two", "v1")] = raw
	if _, ok := readSnapshot[map[string]string](ctx, c, "token", "two", "v1"); ok {
		t.Fatal("accepted substituted ciphertext")
	}
	m.values[key][len(raw)-1] ^= 1
	if _, ok := readSnapshot[map[string]string](ctx, c, "token", "one", "v1"); ok {
		t.Fatal("accepted corrupted ciphertext")
	}
}

func TestSnapshotWarmCacheCannotReplaceSQL(t *testing.T) {
	db := backendDB(t)
	r := NewSessionRepository(db)
	c, m := testSnapshots(t)
	r.WithSnapshotCache(c)
	s := snapshotSessionFixture(t, db, r)
	for range 2 {
		if _, e := r.GetByTokenHash(t.Context(), s.TokenHash); e != nil {
			t.Fatal(e)
		}
	}
	before := m.gets
	if e := db.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := r.GetByTokenHash(t.Context(), s.TokenHash); e == nil {
		t.Fatal("warm cache authenticated without SQL")
	}
	if m.gets != before {
		t.Fatal("consulted cache after SQL failure")
	}
}

func TestCacheVersionAllSessionUpdates(t *testing.T) {
	for _, name := range []string{"touch", "set org", "role", "clear", "clear user", "clear all", "refresh"} {
		t.Run(name, func(t *testing.T) {
			db := backendDB(t)
			r := NewSessionRepository(db)
			s := snapshotSessionFixture(t, db, r)
			now := time.Now().UTC()
			org := uuid.NewString()
			if e := NewOrgRepository(db).Create(t.Context(), &domain.Organization{ID: org, Name: "Cache test", Slug: org, CreatedAt: now, UpdatedAt: now}); e != nil {
				t.Fatal(e)
			}
			if e := r.SetActiveOrg(t.Context(), s.ID, org, domain.OrgRoleMember); e != nil {
				t.Fatal(e)
			}
			c, _ := testSnapshots(t)
			r.WithSnapshotCache(c)
			if _, e := r.GetByTokenHash(t.Context(), s.TokenHash); e != nil {
				t.Fatal(e)
			}
			old := cacheVersion(t, db, "sessions", s.ID)
			var e error
			switch name {
			case "touch":
				e = r.UpdateLastActiveAt(t.Context(), s.TokenHash)
			case "set org":
				e = r.SetActiveOrg(t.Context(), s.ID, org, domain.OrgRoleOwner)
			case "role":
				e = r.UpdateActiveOrgRoleForUser(t.Context(), s.UserID, org, domain.OrgRoleAdmin)
			case "clear":
				e = r.ClearActiveOrg(t.Context(), s.ID)
			case "clear user":
				e = r.ClearActiveOrgForUser(t.Context(), s.UserID, org)
			case "clear all":
				e = r.ClearActiveOrgForAllMembers(t.Context(), org)
			case "refresh":
				_, e = r.UpdateRefreshToken(t.Context(), port.UpdateRefreshInput{OldRefreshHash: s.RefreshTokenHash, NewTokenHash: uuid.NewString(), NewRefreshHash: uuid.NewString(), NewExpiresAt: now.Add(time.Hour), RotatedAt: now})
			}
			if e != nil {
				t.Fatal(e)
			}
			if old == cacheVersion(t, db, "sessions", s.ID) {
				t.Fatal("mutation kept cached identity")
			}
		})
	}
}

func TestCacheVersionAllTokenUpdates(t *testing.T) {
	for _, name := range []string{"mark", "claim", "cap", "attempt", "resend", "consume", "consume capped", "consume unowned"} {
		t.Run(name, func(t *testing.T) {
			db := backendDB(t)
			r := NewTokenRepository(db)
			user := backendUser(t, db)
			now := time.Now().UTC()
			tok := &domain.VerificationToken{ID: uuid.NewString(), UserID: &user, Email: "proof@example.test", TokenHash: uuid.NewString(), Type: domain.TokenTwoFactor, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
			if name == "consume unowned" {
				tok.UserID = nil
			}
			if e := r.Create(t.Context(), tok); e != nil {
				t.Fatal(e)
			}
			old := cacheVersion(t, db, "verification_tokens", tok.ID)
			var e error
			input := port.ConsumeTokenInput{ID: tok.ID, TokenHash: tok.TokenHash, UserID: user, Type: tok.Type, UsedAt: now}
			if tok.UserID == nil {
				input.UserID = ""
			}
			switch name {
			case "mark":
				e = r.MarkUsed(t.Context(), tok.ID)
			case "claim":
				_, e = r.MarkUsedIfUnused(t.Context(), tok.ID)
			case "cap":
				_, e = r.MarkUsedIfUnderCap(t.Context(), tok.ID, 5)
			case "attempt":
				_, e = r.IncrementAttempts(t.Context(), tok.ID, 5)
			case "resend":
				_, e = r.UpdateForResend(t.Context(), tok.ID, "next-hash", now.Add(time.Hour), now, 3, 5)
			case "consume":
				_, e = r.ConsumeIfValid(t.Context(), input)
			default:
				_, e = r.ConsumeIfValidUnderCap(t.Context(), input, 5)
			}
			if e != nil {
				t.Fatal(e)
			}
			if old == cacheVersion(t, db, "verification_tokens", tok.ID) {
				t.Fatal("mutation kept cached identity")
			}
		})
	}
}

func TestCacheVersionOrganizationDeletionClearsRevokedScope(t *testing.T) {
	db := backendDB(t)
	r := NewSessionRepository(db)
	s := snapshotSessionFixture(t, db, r)
	now := time.Now().UTC()
	org := uuid.NewString()
	orgs := NewOrgRepository(db)
	if e := orgs.Create(t.Context(), &domain.Organization{ID: org, Name: "Deleted", Slug: org, CreatedAt: now, UpdatedAt: now}); e != nil {
		t.Fatal(e)
	}
	if e := r.SetActiveOrg(t.Context(), s.ID, org, domain.OrgRoleOwner); e != nil {
		t.Fatal(e)
	}
	if _, e := db.execVersioned(t.Context(), "UPDATE sessions SET is_revoked=true WHERE id=$1", s.ID); e != nil {
		t.Fatal(e)
	}
	c, _ := testSnapshots(t)
	r.WithSnapshotCache(c)
	if _, e := r.GetByTokenHash(t.Context(), s.TokenHash); e != nil {
		t.Fatal(e)
	}
	old := cacheVersion(t, db, "sessions", s.ID)
	if deleted, e := orgs.Delete(t.Context(), org); e != nil || !deleted {
		t.Fatal(deleted, e)
	}
	current, e := r.GetByTokenHash(t.Context(), s.TokenHash)
	if e != nil || current == nil || current.ActiveOrgID != nil || current.ActiveOrgRole != nil || !current.IsRevoked {
		t.Fatalf("stale revoked scope: %+v %v", current, e)
	}
	if old == cacheVersion(t, db, "sessions", s.ID) {
		t.Fatal("FK-related mutation kept old cache identity")
	}
}
