package sqlstore

import (
	"context"
	"database/sql"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// Explicit fields preserve secrets hidden by the domain's public JSON tags.
type sessionSnapshot struct {
	Session      domain.Session `json:"session"`
	TokenHash    string         `json:"tokenHash"`
	RefreshHash  string         `json:"refreshHash"`
	PreviousHash string         `json:"previousHash"`
	Assurance    *time.Time     `json:"assurance"`
}

// WithSnapshotCache enables disposable reads; configure before serving.
func (r *SessionRepository) WithSnapshotCache(c *SnapshotCache) { r.snapshots = c }

func (v *sessionSnapshot) session(id string) *domain.Session {
	s := v.Session
	if s.ID != id || s.UserID == "" || s.ExpiresAt.IsZero() || s.CreatedAt.IsZero() || (s.ActiveOrgID == nil) != (s.ActiveOrgRole == nil) {
		return nil
	}
	s.TokenHash = v.TokenHash
	s.RefreshTokenHash = v.RefreshHash
	s.PreviousRefreshHash = v.PreviousHash
	s.TwoFactorVerifiedAt = v.Assurance
	s.ParsedUA = nil
	finishSession(&s)
	return &s
}

func (r *SessionRepository) cachedSession(ctx context.Context, predicate string, args ...any) (*domain.Session, error) {
	c := r.snapshots
	_, inTx := txFromContext(ctx)
	if c == nil || inTx {
		s := &domain.Session{}
		err := scanSession(s, r.db.QueryRowContext(ctx, "SELECT "+sessionCols+" FROM sessions WHERE "+predicate, args...))
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return s, err
	}
	var id, version string
	err := r.db.QueryRowContext(ctx, "SELECT id, cache_version FROM sessions WHERE "+predicate, args...).Scan(&id, &version)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if v, ok := readSnapshot[sessionSnapshot](ctx, c, "session", id, version); ok {
		if s := v.session(id); s != nil {
			return s, nil
		}
	}
	return r.fillSession(ctx, predicate, args...)
}

func (r *SessionRepository) fillSession(ctx context.Context, predicate string, args ...any) (*domain.Session, error) {
	s := &domain.Session{}
	var version string
	dest := append(sessionScanDest(s), &version)
	err := r.db.QueryRowContext(ctx, "SELECT "+sessionCols+", cache_version FROM sessions WHERE "+predicate, args...).Scan(dest...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	finishSession(s)
	writeSnapshot(ctx, r.snapshots, "session", s.ID, version, sessionSnapshot{Session: *s, TokenHash: s.TokenHash, RefreshHash: s.RefreshTokenHash, PreviousHash: s.PreviousRefreshHash, Assurance: s.TwoFactorVerifiedAt})
	return s, nil
}

func (r *SessionRepository) cachedSessionWithUser(ctx context.Context, hash string) (*domain.Session, *domain.User, error) {
	var id, version string
	u := &domain.User{}
	var n userNullables
	dest := append([]any{&id, &version}, userScanDest(u, &n)...)
	err := r.db.QueryRowContext(ctx, "SELECT s.id, s.cache_version, "+userColsQualified+" FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1", hash).Scan(dest...)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	finishUser(u, &n)
	if r.appPermissions {
		u.Role = ""
	}
	if v, ok := readSnapshot[sessionSnapshot](ctx, r.snapshots, "session", id, version); ok {
		if s := v.session(id); s != nil && s.UserID == u.ID && s.TokenHash == hash {
			return s, u, nil
		}
	}
	// Re-run the joined authoritative read on a miss, so a user mutation
	// between queries cannot be paired with a newer session by accident.
	s := &domain.Session{}
	u = &domain.User{}
	n = userNullables{}
	dest = append(append(sessionScanDest(s), &version), userScanDest(u, &n)...)
	err = r.db.QueryRowContext(ctx, "SELECT "+sessionColsQualified+", s.cache_version, "+userColsQualified+" FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1", hash).Scan(dest...)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	finishSession(s)
	finishUser(u, &n)
	if r.appPermissions {
		u.Role = ""
	}
	writeSnapshot(ctx, r.snapshots, "session", s.ID, version, sessionSnapshot{Session: *s, TokenHash: s.TokenHash, RefreshHash: s.RefreshTokenHash, PreviousHash: s.PreviousRefreshHash, Assurance: s.TwoFactorVerifiedAt})
	return s, u, nil
}
