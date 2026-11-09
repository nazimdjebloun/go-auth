package goauth

// Transport selects the adapters constructed around the authentication services.
type Transport string

// TransportBrowser builds protected browser HTTP routes and helpers.
// TransportServices builds Go services for application-owned transports only.
const (
	TransportBrowser  Transport = "browser"
	TransportServices Transport = "services"
)

// WithTransport selects browser HTTP or service-only construction. Browser is
// the default. This option changes no credential, account, MFA or permission
// policy. Repeated calls replace the selection; WithBrowser does not change it.
func WithTransport(transport Transport) Option {
	return func(c *Config) { c.transport = transport }
}

func (c *Config) browserEnabled() bool {
	// An omitted selection has always requested browser construction. Keeping
	// that meaning before defaulting also supports internal facade fixtures.
	return c.transport == "" || c.transport == TransportBrowser
}

func (c *Config) httpRateLimitEnabled() bool {
	return c.browserEnabled() && c.rateLimit != nil && c.rateLimit.Enabled
}

func (c *Config) validateTransport() []error {
	switch c.transport {
	case "", TransportBrowser, TransportServices:
		return nil
	default:
		return []error{configIssue("Transport", ConfigUnsupported,
			"transport must be TransportBrowser or TransportServices")}
	}
}
