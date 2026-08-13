package ratelimit

import (
	"log/slog"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/routes"
)

type StoreResult struct {
	Count   int
	ResetAt time.Time
}

type Store interface {
	Increment(key string, window time.Duration) (StoreResult, error)
	Reset(key string) error
}

type Config struct {
	Enabled         bool
	Default         Rate
	Routes          map[string]Rate
	Store           Store
	DisabledPaths   []string
	TrustedIPs      []string
	IPv6Subnet      int          // subnet prefix length for IPv6 rate limiting (default 64)
	IPAddressHeader string       // e.g. "CF-Connecting-IP", "X-Real-IP" (default: "X-Forwarded-For")
	Logger          *slog.Logger // structured logger for rate limit store errors; defaults to slog.Default()
}

type Rate struct {
	Requests int
	Window   time.Duration
}

func DefaultRateLimitConfig() *Config {
	return &Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    Rate{Requests: 60, Window: time.Minute},
		Store:      NewMemoryStore(),
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
