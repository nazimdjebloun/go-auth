# Documentation Rules

## Source of truth

Code and tests define implemented behavior. Read them before editing prose. Do
not copy an old documentation claim into a new location without re-verifying
it.

Documentation must preserve precise modality: `must`, `should`, `may`, defaults,
failure behavior, and opt-in/opt-out status are not interchangeable.

## Documentation map

| Change | Update |
|---|---|
| Public setup or first-use experience | `README.md`, `docs/installation.mdx` |
| `With*` option, default, or validation | `docs/configuration.mdx` |
| Route, method, authentication level, body, or cookie | `docs/routes/` and the relevant guide |
| Public error code | `docs/error-handling.mdx` |
| Table, column, index, or driver difference | `docs/schemas.mdx` |
| Security guarantee or operator responsibility | `docs/security.mdx` |
| Package/layer/transaction design | `docs/architecture.mdx` |
| User workflow | the relevant file under `docs/guides/` |

## README role

The README is the project landing page. Keep it concise and executable:

1. State what the library does and its stability.
2. Show installation and one minimal working setup.
3. Explain schema setup.
4. Summarize major features and security defaults.
5. Link to detailed documentation rather than duplicating it.

Compile or otherwise verify code examples where practical. A quick start that
silently omits a required mailer, driver, database migration, or security option
is defective even if each individual line compiles.

## Style

- Prefer direct factual language over marketing claims.
- Explain why and when; avoid restating signatures.
- Use actual exported names and current paths.
- Keep examples internally consistent, including imports, environment, database
  driver, origins, and required configuration.
- Update README and public docs in the same pass as a breaking public change.
