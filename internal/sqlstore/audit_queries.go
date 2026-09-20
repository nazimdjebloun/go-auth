package sqlstore

const (
	auditLogCols = `id, event_type, severity, success, actor_id, target_id,
		session_id, org_id, ip, user_agent, parsed_ua, request_id, correlation_id, metadata, created_at`

	auditLogListQuery = `SELECT ` + auditLogCols + ` FROM audit_log`

	auditLogCountQuery = `SELECT COUNT(*) FROM audit_log`

	auditLogByIDQuery = `SELECT ` + auditLogCols + ` FROM audit_log WHERE id = $1`

	// outboxInsert adds a delivery obligation. The event row itself is written
	// separately (in the same transaction by the record path), so this never
	// carries the payload — claim joins back to audit_log to rebuild it.
	outboxInsert = `INSERT INTO audit_outbox
		(audit_log_id, org_id, priority, attempts, next_attempt_at, claim_owner, last_error, created_at)
		VALUES ($1, $2, $3, 0, $4, '', '', $5)`

	// outboxCandidates selects deliverable rows oldest-priority-first. A row is
	// claimable when it has no live claim: claimed_at is NULL (never claimed or
	// released) or older than the lease cutoff (crashed/slow claimer — the
	// steal is a benign duplicate under at-least-once, counted by the caller).
	// The second column flags rows that already carried a claim, so the
	// dispatcher can count a lease steal as a benign duplicate delivery.
	outboxCandidates = `SELECT o.audit_log_id,
			CASE WHEN o.claimed_at IS NULL THEN 0 ELSE 1 END
		FROM audit_outbox o
		WHERE o.dead_lettered_at IS NULL
		  AND o.next_attempt_at <= $1
		  AND (o.claimed_at IS NULL OR o.claimed_at < $2)
		ORDER BY o.priority, o.next_attempt_at
		LIMIT $3`

	// outboxClaimCAS is the guarded compare-and-swap: only the instance whose
	// UPDATE touches a row owns its delivery for the lease window. RowsAffected
	// decides the winner — no SKIP LOCKED required (SQLite lacks it).
	outboxClaimCAS = `UPDATE audit_outbox
		SET claimed_at = $1, claim_owner = $2, attempts = attempts + 1
		WHERE audit_log_id = $3
		  AND dead_lettered_at IS NULL
		  AND (claimed_at IS NULL OR claimed_at < $4)`

	outboxClaimed = `SELECT o.audit_log_id, o.attempts, o.org_id, a.event_type, a.severity,
			a.success, a.actor_id, a.target_id, a.session_id, a.ip, a.user_agent,
			a.parsed_ua, a.request_id, a.correlation_id, a.metadata, a.created_at
		FROM audit_outbox o JOIN audit_log a ON a.id = o.audit_log_id
		WHERE o.claim_owner = $1`

	outboxDelete       = `DELETE FROM audit_outbox WHERE audit_log_id = $1`
	outboxReleaseClaim = `UPDATE audit_outbox SET claimed_at = NULL, claim_owner = '' WHERE audit_log_id = $1`

	outboxRetry = `UPDATE audit_outbox
		SET next_attempt_at = $1, last_error = $2, claimed_at = NULL, claim_owner = ''
		WHERE audit_log_id = $3`

	outboxDeadLetter = `UPDATE audit_outbox
		SET dead_lettered_at = $1, last_error = $2, claimed_at = NULL, claim_owner = ''
		WHERE audit_log_id = $3`

	// outboxSweepExpired enforces the two outbox clocks in one pass: pending
	// rows older than OutboxMaxAge are evicted (delivery abandoned, record
	// intact), dead-lettered rows older than DeadLetterTTL are purged (their
	// evidence window elapsed). Returns both counts. The caller passes the
	// cutoffs as RFC3339 strings so the comparison is text-to-text on SQLite
	// (which stores timestamps as RFC3339 strings) and coerces cleanly to a
	// real timestamp on MySQL/Postgres.
	outboxSweepExpired = `SELECT
			COALESCE(SUM(CASE WHEN dead_lettered_at IS NULL THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN dead_lettered_at IS NOT NULL THEN 1 ELSE 0 END), 0)
		FROM audit_outbox
		WHERE (dead_lettered_at IS NULL AND created_at < $1)
		   OR (dead_lettered_at IS NOT NULL AND dead_lettered_at < $2)`

	outboxSweepDelete = `DELETE FROM audit_outbox
		WHERE (dead_lettered_at IS NULL AND created_at < $1)
		   OR (dead_lettered_at IS NOT NULL AND dead_lettered_at < $2)`

	// outboxCountTotal backs OutboxMaxRows: the emergency valve never reads
	// audit_log, so a full backlog cannot damage the record.
	outboxCountTotal = `SELECT COUNT(*) FROM audit_outbox`

	// outboxEvictCandidates lists rows the emergency valve may shed, oldest
	// first. The caller deletes them by id rather than with a
	// DELETE ... WHERE id IN (SELECT ... LIMIT n): MySQL rejects a LIMIT in
	// an IN subquery (ERROR 1235) and warns about deleting from a table
	// named in its own subquery, so select-then-delete is the portable
	// shape (the same one PurgeOrphans uses).
	outboxEvictCandidates = `SELECT audit_log_id FROM audit_outbox ORDER BY created_at, audit_log_id LIMIT $1`

	// outboxEvictDeadCandidates lists dead-lettered rows first: shedding an
	// already-lost delivery costs no new harm.
	outboxEvictDeadCandidates = `SELECT audit_log_id FROM audit_outbox
		WHERE dead_lettered_at IS NOT NULL
		ORDER BY dead_lettered_at, audit_log_id LIMIT $1`

	outboxPendingCount = `SELECT COUNT(*) FROM audit_outbox WHERE dead_lettered_at IS NULL`

	outboxOldestPending = `SELECT MIN(created_at) FROM audit_outbox WHERE dead_lettered_at IS NULL`

	// outboxOrphans finds obligations whose record no longer exists. Under
	// record-iff-commit these can only come from bypassed retention validation
	// or manual deletes — a non-zero rate signals a broken invariant, so the
	// caller counts them as delivery_orphaned, distinct from delivery_dropped.
	outboxOrphanIDs = `SELECT o.audit_log_id FROM audit_outbox o
		LEFT JOIN audit_log a ON a.id = o.audit_log_id
		WHERE a.id IS NULL LIMIT $1`
)
