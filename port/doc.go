// Package port declares the interfaces go-auth's service layer depends on
// instead of concrete implementations — Mailer, OAuthProvider,
// TemplateProvider, Hasher, TokenGenerator, TxManager, and the *Repository
// interfaces backing storage. Swappable behavior is limited to the
// documented seams (a custom mailer, a third-party OAuth provider, a
// different password hash, custom templates, a rate-limit store, audit
// sinks). Storage itself is SQL-only: the repository interfaces describe
// what the built-in sqlstore already guarantees, not an extension point
// for non-SQL stores.
package port
