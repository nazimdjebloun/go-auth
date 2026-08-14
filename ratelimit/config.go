package ratelimit

import (
	"context"
	"log/slog"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/routes"
)

// Result is one rate-limit decision.
//
// The store decides, rather than handing back a raw count for the caller to
// compare: a distributed backend has to make the decision atomically with the
// increment anyway (a Redis round-trip that returns a count, then a local
// comparison, is a race), and the in-memory store needs the limit at write
// time regardless — its eviction policy ranks entries by how much of their
// budget is left, which is unknowable from a count alone.
type Result struct {
	Allowed   bool
	Remaining int // requests left in this window, never negative
	ResetAt   time.Time
}

// Store holds rate-limit counters. The default implementation is in-process
// (NewMemoryStore); implement this against Redis or similar to share limits
// across instances — see docs/guides/rate-limiting.mdx.
//
// Allow must be safe for concurrent use and must count the current request:
// it returns the decision *including* this call.
//
// # One key, one Rate
//
// A given key must always be passed the same Rate. A store is free to keep
// per-key state derived from the first Rate it sees — the in-memory store
// keeps both the window end (so a key's window doesn't slide forward on every
// call) and the limit (so eviction can rank a counter by how much budget it
// has left). Passing two different Rates for one key doesn't corrupt the
// decision, which always uses the Rate handed to the call, but it does make
// that derived state depend on call order. The middleware upholds this by
// putting the route pattern in the key; a caller using a Store directly, or
// sharing one Store across two Configs with different tables, has to uphold
// it itself.
//
// # Context
//
// ctx carries the deadline and cancellation of the request being limited —
// middleware.RateLimit passes r.Context(). An implementation that performs
// I/O should honour it, with one caveat worth designing for up front: that
// context is cancelled when the *client* disconnects, and the middleware
// fails closed, so returning ctx.Err() unconditionally turns every abandoned
// request into a 429 plus a logged store error. Prefer a bounded timeout
// derived from ctx over propagating raw cancellation, and distinguish
// context.Canceled from a genuine backend failure.
type Store interface {
	Allow(ctx context.Context, key string, rate Rate) (Result, error)
}

type Config struct {
	Enabled         bool
	Default         Rate
	Routes          map[string]Rate
	Store           Store // optional; an in-memory store is created if nil
	DisabledPaths   []string
	TrustedIPs      []string
	IPv6Subnet      int          // subnet prefix length for IPv6 rate limiting (default 64)
	IPAddressHeader string       // e.g. "CF-Connecting-IP", "X-Real-IP" (default: "" — RemoteAddr only)
	Logger          *slog.Logger // structured logger for rate limit store errors; defaults to slog.Default()
}

type Rate struct {
	Requests int
	Window   time.Duration
}

// DefaultRateLimitConfig returns the built-in configuration. It deliberately
// leaves Store nil: constructing one here starts a background goroutine, and
// every WithRateLimit* option calls this function to lazily seed a config,
// so an eager store meant each of those options orphaned a goroutine nothing
// could ever close. The store is created once, later, by whoever ends up
// using the config (config.applyDefaults, or middleware.RateLimit for a
// hand-built Config).
func DefaultRateLimitConfig() *Config {
	return &Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    Rate{Requests: 60, Window: time.Minute},
		Routes: map[string]Rate{
			// Login / register
			routes.Glob(routes.Login):      {Requests: 5, Window: time.Minute},
			routes.Glob(routes.AdminLogin): {Requests: 3, Window: time.Minute},
			routes.Glob(routes.Register):   {Requests: 3, Window: time.Minute},
			// Password / verification
			routes.Glob(routes.ForgotPassword):           {Requests: 3, Window: time.Hour},
			routes.Glob(routes.ResetPassword):            {Requests: 5, Window: time.Minute},
			routes.Glob(routes.VerifyEmail):              {Requests: 10, Window: time.Minute},
			routes.Glob(routes.ResendVerificationPublic): {Requests: 3, Window: time.Minute},
			routes.Glob(routes.ResendVerification):       {Requests: 3, Window: time.Minute},
			routes.Glob(routes.SetPasswordRequest):       {Requests: 3, Window: 15 * time.Minute},
			routes.Glob(routes.SetPasswordConfirm):       {Requests: 5, Window: 10 * time.Minute},
			routes.Glob(routes.RequestDeleteAccount):     {Requests: 3, Window: time.Hour},
			routes.Glob(routes.ConfirmDeleteAccount):     {Requests: 3, Window: time.Hour},
			// Invites / refresh
			routes.Glob(routes.InviteRegister): {Requests: 10, Window: time.Minute},
			routes.Glob(routes.InviteInfo):     {Requests: 30, Window: time.Minute},
			routes.Glob(routes.RefreshToken):   {Requests: 3, Window: time.Minute},
			// Two-factor
			routes.Glob(routes.TwoFactorVerify):  {Requests: 5, Window: time.Minute},
			routes.Glob(routes.TwoFactorResend):  {Requests: 3, Window: time.Minute},
			routes.Glob(routes.TwoFactorEnable):  {Requests: 5, Window: time.Minute},
			routes.Glob(routes.TwoFactorDisable): {Requests: 5, Window: time.Minute},
			// Organizations — one entry per actual route, not a subtree catch-all
			routes.Glob(routes.CreateOrg):           {Requests: 5, Window: time.Hour},
			routes.Glob(routes.GetOrg):              {Requests: 60, Window: time.Minute},
			routes.Glob(routes.UpdateOrg):           {Requests: 10, Window: time.Minute},
			routes.Glob(routes.DeleteOrg):           {Requests: 5, Window: time.Minute},
			routes.Glob(routes.ListOrgMembers):      {Requests: 60, Window: time.Minute},
			routes.Glob(routes.RemoveOrgMember):     {Requests: 5, Window: time.Minute},
			routes.Glob(routes.UpdateOrgMemberRole): {Requests: 10, Window: time.Minute},
			routes.Glob(routes.LeaveOrg):            {Requests: 30, Window: time.Minute},
			routes.Glob(routes.SetActiveOrg):        {Requests: 10, Window: time.Minute},
			routes.Glob(routes.ClearActiveOrg):      {Requests: 5, Window: time.Minute},
			routes.Glob(routes.CreateOrgInvite):     {Requests: 20, Window: time.Hour},
			routes.Glob(routes.AcceptOrgInvite):     {Requests: 30, Window: time.Minute},
			routes.Glob(routes.ListOrgInvites):      {Requests: 30, Window: time.Minute},
			routes.Glob(routes.ResendOrgInvite):     {Requests: 30, Window: time.Minute},
			routes.Glob(routes.DeleteOrgInvite):     {Requests: 10, Window: time.Minute},
			// Admin endpoints
			routes.Glob(routes.ListUsers):              {Requests: 60, Window: time.Minute},
			routes.Glob(routes.AdminCreateUser):        {Requests: 10, Window: time.Minute},
			routes.Glob(routes.UpdateUserRole):         {Requests: 30, Window: time.Minute},
			routes.Glob(routes.BanUser):                {Requests: 30, Window: time.Minute},
			routes.Glob(routes.UnbanUser):              {Requests: 30, Window: time.Minute},
			routes.Glob(routes.DeleteUser):             {Requests: 10, Window: time.Minute},
			routes.Glob(routes.AdminListUserSessions):  {Requests: 60, Window: time.Minute},
			routes.Glob(routes.RevokeUserSessions):     {Requests: 20, Window: time.Minute},
			routes.Glob(routes.AdminRevokeUserSession): {Requests: 20, Window: time.Minute},
			routes.Glob(routes.CreateInvite):           {Requests: 10, Window: time.Minute},
			routes.Glob(routes.ListInvites):            {Requests: 60, Window: time.Minute},
			routes.Glob(routes.RevokeInvite):           {Requests: 10, Window: time.Minute},
			routes.Glob(routes.HardDeleteInvite):       {Requests: 10, Window: time.Minute},
			routes.Glob(routes.ResendInvite):           {Requests: 5, Window: time.Minute},
		},
	}
}
