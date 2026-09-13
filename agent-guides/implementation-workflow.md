# Implementation Workflow

Follow this sequence for feature work.

1. **Explore the analogous feature.** Read its route, wiring, handler, service,
   port interfaces, repository, schema, tests, and documentation.
2. **Design the narrow port first.** A service should depend only on the reader,
   writer, counter, or transaction capability it uses, not an oversized composed
   repository.
3. **Implement business behavior in `internal/service`.** Use a per-method input
   struct for non-trivial operations. Carry actor IDs in that input when
   authorization or audit context requires them.
4. **Use the established error contract.** User-facing failures use stable
   `domain.AuthError` codes. Infrastructure failures wrap their cause and must
   not be disguised as not-found or invalid-input errors.
5. **Map every new public error.** Add the sentinel in `domain/errors.go` and its
   status in `internal/httperr/httperr.go`. The repository test that scans error
   constructors must remain green.
6. **Keep handlers thin.** Decode camelCase JSON, call the service, use the shared
   error writer, and set cookies through middleware helpers.
7. **Wire the route explicitly.** Add canonical metadata in `internal/routes`,
   then add the handler with its exact middleware chain. A rate-limit config
   entry alone does not protect a route.
8. **Update persistence.** Change all three embedded schemas when the data model
   changes and implement the repository behind a narrow port. Use transactions
   rather than manually coordinating dependent statements.
9. **Test behavior and failures.** Add service tests, handler tests for HTTP
   shape, repository tests for SQL invariants, and SQLite integration tests for
   end-to-end HTTP behavior when applicable.
10. **Update public documentation after behavior is green.** Verify signatures,
    defaults, error codes, and security claims directly from the implementation.
11. **Run the complete checks in both Go modules.** Follow `testing.md`.

## Service rules

- Prefer `(Result, error)` over returning `*domain.AuthError` as the declared
  error type.
- Never collapse repository failure into absence. A database error is an
  internal failure, not a 404.
- Publish audit events according to the existing audit contract. Do not move an
  event inside a database transaction unless the design explicitly uses a
  durable outbox.
- Reuse established helpers for transaction, credential, timing, and token
  invariants. Do not implement the same security rule independently in three
  call sites.
