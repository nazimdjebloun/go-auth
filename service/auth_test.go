package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type mockUserRepo struct {
	mu    sync.Mutex
	users map[string]*domain.User
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: make(map[string]*domain.User)}
}

func (m *mockUserRepo) Create(ctx context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.users[user.Email] = user
	return nil
}

func (m *mockUserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (m *mockUserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[email]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (m *mockUserRepo) Update(ctx context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.users[user.Email] = user
	return nil
}

func (m *mockUserRepo) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[id]
	if u != nil {
		delete(m.users, u.Email)
	}
	delete(m.users, id)
	return nil
}

func (m *mockUserRepo) List(ctx context.Context, filter port.UserFilter) ([]domain.User, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// simplified for test
	return nil, 0, nil
}

type mockSessionRepo struct {
	mu       sync.Mutex
	sessions map[string]*domain.Session
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{sessions: make(map[string]*domain.Session)}
}

func (m *mockSessionRepo) Create(ctx context.Context, s *domain.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
	m.sessions[s.TokenHash] = s
	return nil
}

func (m *mockSessionRepo) GetByTokenHash(ctx context.Context, hash string) (*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return nil, nil
	}
	return s, nil
}

func (m *mockSessionRepo) ListByUserID(ctx context.Context, userID string) ([]domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []domain.Session
	for _, s := range m.sessions {
		if s.UserID == userID && !s.IsRevoked {
			result = append(result, *s)
		}
	}
	return result, nil
}

func (m *mockSessionRepo) Revoke(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if ok {
		s.IsRevoked = true
	}
	return nil
}

func (m *mockSessionRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		if s.UserID == userID {
			s.IsRevoked = true
		}
	}
	return nil
}

func (m *mockSessionRepo) DeleteExpired(ctx context.Context) error {
	return nil
}

type mockTokenRepo struct {
	mu     sync.Mutex
	tokens map[string]*domain.VerificationToken
}

func newMockTokenRepo() *mockTokenRepo {
	return &mockTokenRepo{tokens: make(map[string]*domain.VerificationToken)}
}

func (m *mockTokenRepo) Create(ctx context.Context, t *domain.VerificationToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.ID] = t
	m.tokens[t.TokenHash] = t
	return nil
}

func (m *mockTokenRepo) GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[hash]
	if !ok {
		return nil, nil
	}
	return t, nil
}

func (m *mockTokenRepo) MarkUsed(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if ok {
		now := time.Now().UTC()
		t.UsedAt = &now
	}
	return nil
}

func (m *mockTokenRepo) DeleteExpired(ctx context.Context) error {
	return nil
}

type mockHasher struct{}

func (m *mockHasher) Hash(password string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:]), nil
}

func (m *mockHasher) Compare(password, hash string) error {
	sum := sha256.Sum256([]byte(password))
	if hex.EncodeToString(sum[:]) != hash {
		return domain.ErrInvalidCredentials
	}
	return nil
}

type mockTokenGen struct {
	length int
}

func (m *mockTokenGen) Generate() (string, string, error) {
	b := make([]byte, m.length)
	rand.Read(b)
	raw := hex.EncodeToString(b)
	return raw, m.Hash(raw), nil
}

func (m *mockTokenGen) Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

type mockInviteRepo struct {
	mu      sync.Mutex
	invites map[string]*domain.Invite
}

func newMockInviteRepo() *mockInviteRepo {
	return &mockInviteRepo{invites: make(map[string]*domain.Invite)}
}

func (m *mockInviteRepo) Create(ctx context.Context, invite *domain.Invite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invites[invite.ID] = invite
	m.invites[invite.Code] = invite
	m.invites["email:"+invite.Email] = invite
	return nil
}

func (m *mockInviteRepo) GetByID(ctx context.Context, id string) (*domain.Invite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[id]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

func (m *mockInviteRepo) GetByCode(ctx context.Context, code string) (*domain.Invite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[code]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

func (m *mockInviteRepo) GetByEmail(ctx context.Context, email string) (*domain.Invite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites["email:"+email]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

func (m *mockInviteRepo) List(ctx context.Context, offset, limit int) ([]domain.Invite, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []domain.Invite
	for _, inv := range m.invites {
		if inv.ID != "" && inv.Code != "" {
			result = append(result, *inv)
		}
	}
	return result, len(result), nil
}

func (m *mockInviteRepo) Update(ctx context.Context, invite *domain.Invite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invites[invite.ID] = invite
	m.invites[invite.Code] = invite
	m.invites["email:"+invite.Email] = invite
	return nil
}

func defaultTestConfig() Config {
	return Config{
		AppName:             "TestApp",
		InviteTTL:           7 * 24 * time.Hour,
		VerificationCodeTTL: 15 * time.Minute,
		SessionTTL:          30 * 24 * time.Hour,
		TokenTTL:            1 * time.Hour,
		BcryptCost:          4,
		TokenLength:         32,
	}
}

func TestRegister(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig())

	result, err := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if result.User == nil {
		t.Fatal("Expected user, got nil")
	}
	if result.User.Email != "test@example.com" {
		t.Fatalf("Expected email test@example.com, got %s", result.User.Email)
	}
	if result.Session == nil {
		t.Fatal("Expected session, got nil")
	}
	if result.SessionToken == "" {
		t.Fatal("Expected session token, got empty")
	}
	if result.User.Role != domain.RoleUser {
		t.Fatalf("Expected role user, got %s", result.User.Role)
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig())

	svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test",
	})

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "password456",
		Name:     "Test 2",
	})
	if err == nil {
		t.Fatal("Expected error for duplicate email, got nil")
	}
	if err.Code != "email_already_exists" {
		t.Fatalf("Expected email_already_exists, got %s", err.Code)
	}
}

func TestRegisterWeakPassword(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig())

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "short",
		Name:     "Test",
	})
	if err == nil {
		t.Fatal("Expected error for weak password, got nil")
	}
}

func TestRegisterInvalidEmail(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig())

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "not-an-email",
		Password: "password123",
		Name:     "Test",
	})
	if err == nil {
		t.Fatal("Expected error for invalid email, got nil")
	}
}

func TestRegisterAdminSeed(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	cfg := defaultTestConfig()
	cfg.AdminEmails = []string{"admin@example.com"}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, cfg)

	result, err := svc.Register(context.Background(), RegisterInput{
		Email:    "admin@example.com",
		Password: "password123",
		Name:     "Admin",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if result.User.Role != domain.RoleAdmin {
		t.Fatalf("Expected role admin, got %s", result.User.Role)
	}
}

func TestRegisterInviteOnly(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	cfg := defaultTestConfig()
	cfg.InviteOnly = true

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, cfg)

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test",
	})
	if err == nil {
		t.Fatal("Expected error for invite-only mode, got nil")
	}
}

func TestLogin(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig())

	svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test",
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email:    "test@example.com",
		Password: "password123",
		IP:       "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if result.User == nil {
		t.Fatal("Expected user, got nil")
	}
	if result.SessionToken == "" {
		t.Fatal("Expected session token, got empty")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig())

	svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test",
	})

	_, err := svc.Login(context.Background(), LoginInput{
		Email:    "test@example.com",
		Password: "wrongpassword",
	})
	if err == nil {
		t.Fatal("Expected error for wrong password, got nil")
	}
}

func TestLoginNonexistentUser(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig())

	_, err := svc.Login(context.Background(), LoginInput{
		Email:    "nobody@example.com",
		Password: "password123",
	})
	if err == nil {
		t.Fatal("Expected error for nonexistent user, got nil")
	}
}

func TestValidateSession(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig())

	registerResult, _ := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test",
	})

	user, session, err := svc.ValidateSession(context.Background(), registerResult.SessionToken)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}
	if user == nil {
		t.Fatal("Expected user, got nil")
	}
	if session == nil {
		t.Fatal("Expected session, got nil")
	}
	if user.ID != registerResult.User.ID {
		t.Fatalf("Expected user ID %s, got %s", registerResult.User.ID, user.ID)
	}
}

func TestValidateSessionInvalidToken(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig())

	_, _, err := svc.ValidateSession(context.Background(), "invalid-token")
	if err == nil {
		t.Fatal("Expected error for invalid token, got nil")
	}
}

func TestLogout(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig())

	result, _ := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test",
	})

	err := svc.Logout(context.Background(), result.Session.ID)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// session should be expired now
	_, _, err = svc.ValidateSession(context.Background(), result.SessionToken)
	if err == nil {
		t.Fatal("Expected session to be invalid after logout")
	}
}

func TestInviteRegister(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	invites := newMockInviteRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewInviteService(users, sessions, invites, hasher, gen, nil, defaultTestConfig())

	// Create invite
	inviteResult, err := svc.CreateInvite(context.Background(), CreateInviteInput{
		Email:   "invited@example.com",
		AdminID: "admin-id",
	})
	if err != nil {
		t.Fatalf("CreateInvite failed: %v", err)
	}
	if inviteResult == nil {
		t.Fatal("Expected invite, got nil")
	}

	// Complete registration with the code stored in invite.Code (which is the hash)
	// We need the raw token to register. In real flow, the email sends the raw token.
	// Let's generate a raw token and store it properly.
	raw, hash, _ := gen.Generate()
	inviteResult.Code = hash
	invites.Update(context.Background(), inviteResult)

	result, err := svc.CompleteInviteRegistration(context.Background(), CompleteInviteInput{
		Code:            raw,
		Name:            "Invited User",
		Password:        "password123",
		ConfirmPassword: "password123",
	})
	if err != nil {
		t.Fatalf("CompleteInviteRegistration failed: %v", err)
	}
	if result.User == nil {
		t.Fatal("Expected user, got nil")
	}
	if result.User.Email != "invited@example.com" {
		t.Fatalf("Expected email invited@example.com, got %s", result.User.Email)
	}
	if !result.User.IsVerified {
		t.Fatal("Expected user to be auto-verified")
	}
	if result.SessionToken == "" {
		t.Fatal("Expected session token, got empty")
	}
}

func TestInviteRegisterExpired(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	invites := newMockInviteRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	cfg := defaultTestConfig()
	cfg.InviteTTL = -1 * time.Hour // expired

	svc := NewInviteService(users, sessions, invites, hasher, gen, nil, cfg)

	raw, hash, _ := gen.Generate()
	now := time.Now().UTC()
	inviteResult := &domain.Invite{
		ID:        generateID(),
		Email:     "invited@example.com",
		Code:      hash,
		CreatedBy: "admin-id",
		Status:    domain.InvitePending,
		ExpiresAt: now.Add(cfg.InviteTTL),
		CreatedAt: now,
	}
	invites.Create(context.Background(), inviteResult)

	_, err := svc.CompleteInviteRegistration(context.Background(), CompleteInviteInput{
		Code:            raw,
		Name:            "Invited User",
		Password:        "password123",
		ConfirmPassword: "password123",
	})
	if err == nil {
		t.Fatal("Expected error for expired invite, got nil")
	}
	if err.Code != "invite_expired" {
		t.Fatalf("Expected invite_expired, got %s", err.Code)
	}
}

func TestInviteRegisterPasswordMismatch(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	invites := newMockInviteRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{length: 32}

	svc := NewInviteService(users, sessions, invites, hasher, gen, nil, defaultTestConfig())

	raw, hash, _ := gen.Generate()
	inviteResult := &domain.Invite{
		ID:        generateID(),
		Email:     "invited@example.com",
		Code:      hash,
		CreatedBy: "admin-id",
		Status:    domain.InvitePending,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	invites.Create(context.Background(), inviteResult)

	_, err := svc.CompleteInviteRegistration(context.Background(), CompleteInviteInput{
		Code:            raw,
		Name:            "Invited User",
		Password:        "password123",
		ConfirmPassword: "different",
	})
	if err == nil {
		t.Fatal("Expected error for password mismatch, got nil")
	}
	if err.Code != "passwords_dont_match" {
		t.Fatalf("Expected passwords_dont_match, got %s", err.Code)
	}
}
