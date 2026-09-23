package goauth

import "github.com/nazimdjebloun/go-auth/mailer"

// EmailConfig and TLSMode live in the mailer package, beside the SMTP client
// that reads them — the same place every other port implementation keeps its
// own config. They are aliased here because WithEmail takes an EmailConfig,
// so goauth.EmailConfig is the name a consumer writes.
type EmailConfig = mailer.Config

// TLSMode selects the SMTP transport security mode.
type TLSMode = mailer.TLSMode

// TLSStart and the following values select SMTP transport security.
const (
	TLSStart    = mailer.TLSStart
	TLSImplicit = mailer.TLSImplicit
	TLSNone     = mailer.TLSNone
)
