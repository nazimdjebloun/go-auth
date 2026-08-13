// Package port declares the interfaces go-auth's service layer depends on
// instead of concrete implementations — Mailer, OAuthProvider,
// TemplateProvider, Hasher, TokenGenerator, TxManager, and the *Repository
// interfaces backing storage. Implement one of these to swap the built-in
// behavior (a custom mailer, a third-party OAuth provider, a different
// password hash, a non-SQL store) without forking the library; auth.go
// wires the built-in implementations (SMTP mailer, bcrypt hasher, the
// embedded email templates, sqlstore's SQL repositories) into these same
// interfaces, so a replacement is a drop-in.
package port
