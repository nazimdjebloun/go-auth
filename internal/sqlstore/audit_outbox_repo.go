package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
	"unicode/utf8"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/id"
)

// OutboxRepository implements audit.OutboxStore over the audit_outbox table.
// Every method goes through DB.ExecContext/QueryContext, so a call made with a
// ctx derived from WithTx runs inside the caller's transaction — which is what
// makes the record-iff-commit invariant possible for the insert.
type OutboxRepository struct {
	db *DB
}

func NewOutboxRepository(db *DB) *OutboxRepository {
	return &OutboxRepository{db: db}
}

var _ audit.OutboxStore = (*OutboxRepository)(nil)

// Insert records a delivery obligation. Called with the record's transaction
// when one exists, so the obligation commits or rolls back with the record.
func (r *OutboxRepository) Insert(ctx context.Context, eventID string, orgID *string, priority int, now time.Time) error {
	_, err := r.db.ExecContext(ctx, outboxInsert, eventID, orgID, priority, now.UTC(), now.UTC())
	if err != nil {
		return fmt.Errorf("outbox insert: %w", err)
	}
	return nil
}

// ClaimBatch claims up to batchSize deliverable rows for owner. The claim is a
// guarded CAS on each candidate: only the instance whose UPDATE touches the
// row owns it for the lease window. A claimer that crashed (or overstayed its
// lease) loses the row to whoever claims next — a benign duplicate under
// at-least-once delivery, counted as delivery_duplicated by the dispatcher.
func (r *OutboxRepository) ClaimBatch(ctx context.Context, owner string, batchSize int, lease time.Duration) ([]audit.OutboxRow, error) {
	now := time.Now().UTC()
	leaseCutoff := now.Add(-lease)

	rows, err := r.db.QueryContext(ctx, outboxCandidates, now, leaseCutoff, batchSize)
	if err != nil {
		return nil, fmt.Errorf("outbox candidates: %w", err)
	}
	var candidateIDs []string
	var candidateStolen []bool
	for rows.Next() {
		var id string
		var wasClaimed int
		if err := rows.Scan(&id, &wasClaimed); err != nil {
			rows.Close()
			return nil, err
		}
		candidateIDs = append(candidateIDs, id)
		candidateStolen = append(candidateStolen, wasClaimed == 1)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	claimTime := time.Now().UTC()
	// Every ClaimBatch call gets a unique token. Re-reading by the token is
	// robust across drivers that round DATETIME values (notably MySQL): an
	// exact claimed_at equality can otherwise lose rows immediately after a
	// successful claim. The dispatcher owner remains as a readable prefix.
	claimToken := owner + ":" + id.New()
	var won []string
	var wonStolen []bool
	for i, id := range candidateIDs {
		res, err := r.db.ExecContext(ctx, outboxClaimCAS, claimTime, claimToken, id, leaseCutoff)
		if err != nil {
			return nil, fmt.Errorf("outbox claim: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("outbox claim rows affected: %w", err)
		}
		if n > 0 {
			won = append(won, id)
			wonStolen = append(wonStolen, candidateStolen[i])
		}
	}
	if len(won) == 0 {
		return nil, nil
	}

	// Re-read the claimed rows joined to their records, rebuilding the events.
	claimed, err := r.db.QueryContext(ctx, outboxClaimed, claimToken)
	if err != nil {
		return nil, fmt.Errorf("outbox claimed rows: %w", err)
	}
	defer claimed.Close()

	stolenByID := make(map[string]bool, len(won))
	for i, id := range won {
		stolenByID[id] = wonStolen[i]
	}

	var out []audit.OutboxRow
	for claimed.Next() {
		row, e, err := scanClaimedRow(claimed)
		if err != nil {
			return nil, err
		}
		row.Event = e
		row.Stolen = stolenByID[row.EventID]
		out = append(out, row)
	}
	return out, claimed.Err()
}

// MarkSuccess deletes the obligation: the row's existence *was* the pending
// state, so delivery bookkeeping disappears the moment it has no future value.
func (r *OutboxRepository) MarkSuccess(ctx context.Context, eventID string) error {
	_, err := r.db.ExecContext(ctx, outboxDelete, eventID)
	if err != nil {
		return fmt.Errorf("outbox success: %w", err)
	}
	return nil
}

// MarkFailure schedules the next attempt with backoff and records the error
// for operators. The claim is released so another instance (or this one after
// a restart) can pick the row up when next_attempt_at arrives.
func (r *OutboxRepository) MarkFailure(ctx context.Context, eventID string, nextAttemptAt time.Time, lastErr string) error {
	_, err := r.db.ExecContext(ctx, outboxRetry, nextAttemptAt.UTC(), truncateErr(lastErr), eventID)
	if err != nil {
		return fmt.Errorf("outbox retry: %w", err)
	}
	return nil
}

// MarkDeadLetter retains the row with a terminal-failure timestamp so the
// failure evidence survives restarts, until DeadLetterTTL purges it.
func (r *OutboxRepository) MarkDeadLetter(ctx context.Context, eventID string, deadLetteredAt time.Time, lastErr string) error {
	_, err := r.db.ExecContext(ctx, outboxDeadLetter, deadLetteredAt.UTC(), truncateErr(lastErr), eventID)
	if err != nil {
		return fmt.Errorf("outbox dead-letter: %w", err)
	}
	return nil
}

// ReleaseClaim gives a claimed-but-undeliverable row back without counting an
// attempt (e.g. the record vanished before delivery).
func (r *OutboxRepository) ReleaseClaim(ctx context.Context, eventID string) error {
	_, err := r.db.ExecContext(ctx, outboxReleaseClaim, eventID)
	return err
}

// PurgeOrphans removes obligations whose record no longer exists and reports
// how many were found. A non-zero rate means a broken invariant (bypassed
// retention validation, manual deletes) — the dispatcher alerts on it.
func (r *OutboxRepository) PurgeOrphans(ctx context.Context, limit int) (int, error) {
	rows, err := r.db.QueryContext(ctx, outboxOrphanIDs, limit)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	purged := 0
	for _, id := range ids {
		if _, err := r.db.ExecContext(ctx, outboxDelete, id); err != nil {
			// Report the count actually purged, not a fabricated total.
			return purged, err
		}
		purged++
	}
	return purged, nil
}

func (r *OutboxRepository) CountPending(ctx context.Context) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, outboxPendingCount).Scan(&n)
	return n, err
}

func (r *OutboxRepository) OldestPendingAge(ctx context.Context, now time.Time) (time.Duration, bool, error) {
	var oldest sql.NullTime
	if err := r.db.QueryRowContext(ctx, outboxOldestPending).Scan(&oldest); err != nil {
		return 0, false, err
	}
	if !oldest.Valid {
		return 0, false, nil
	}
	age := now.Sub(oldest.Time)
	if age < 0 {
		age = 0
	}
	return age, true, nil
}

// truncateErr bounds last_error for storage. It truncates on a rune
// boundary: slicing at a byte offset can split a multi-byte rune and write
// invalid UTF-8, which Postgres rejects at the wire.
func truncateErr(msg string) string {
	const max = 512
	if len(msg) <= max {
		return msg
	}
	// Walk back from the byte limit to the last rune start so the cut never
	// lands mid-rune.
	cut := max - 3
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut] + "..."
}

// storedUserAgent is the audit_log.parsed_ua on-disk shape. Audit rows are
// retained, not replaced the way a session row is on its next refresh, so
// unlike domain.UserAgentInfo (which is also the wire shape of
// Session.ParsedUA) this is a separate frozen type: a future change to that
// struct's JSON tags can never silently change what's already on disk in
// this column. Add fields here explicitly if domain.UserAgentInfo grows one
// worth persisting.
type storedUserAgent struct {
	Browser        string `json:"browser"`
	BrowserVersion string `json:"browserVersion,omitempty"`
	OS             string `json:"os"`
	OSVersion      string `json:"osVersion,omitempty"`
	DeviceType     string `json:"deviceType"`
}

func newStoredUserAgent(u *domain.UserAgentInfo) *storedUserAgent {
	if u == nil {
		return nil
	}
	return &storedUserAgent{
		Browser:        u.BrowserName,
		BrowserVersion: u.BrowserVersion,
		OS:             u.OS,
		OSVersion:      u.OSVersion,
		DeviceType:     u.DeviceType,
	}
}

func scanClaimedRow(claimed *sql.Rows) (audit.OutboxRow, audit.Event, error) {
	var (
		row      audit.OutboxRow
		e        audit.Event
		orgID    sql.NullString
		actorID  sql.NullString
		targetID sql.NullString
		sessID   sql.NullString
		ip       sql.NullString
		parsedUA sql.NullString
		metadata sql.NullString
	)
	if err := claimed.Scan(
		&row.EventID, &row.Attempts, &orgID,
		&e.Type, &e.Severity, &e.Success,
		&actorID, &targetID, &sessID, &ip, &e.UserAgent,
		&parsedUA, &e.RequestID, &e.CorrelationID,
		&metadata, &e.CreatedAt,
	); err != nil {
		return row, e, err
	}
	e.ID = row.EventID
	if orgID.Valid && orgID.String != "" {
		v := orgID.String
		e.OrgID = &v
	}
	if actorID.Valid && actorID.String != "" {
		v := actorID.String
		e.ActorID = &v
	}
	if targetID.Valid && targetID.String != "" {
		v := targetID.String
		e.TargetUserID = &v
	}
	if sessID.Valid && sessID.String != "" {
		v := sessID.String
		e.SessionID = &v
	}
	if ip.Valid && ip.String != "" {
		e.IP = net.ParseIP(ip.String)
	}
	if parsedUA.Valid && parsedUA.String != "" {
		var ua domain.UserAgentInfo
		if err := json.Unmarshal([]byte(parsedUA.String), &ua); err == nil {
			e.ParsedUA = &ua
		}
	}
	if metadata.Valid && metadata.String != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(metadata.String), &m); err == nil {
			e.Metadata = m
		}
	}
	return row, e, nil
}

// cutoffStr formats a sweep cutoff as RFC3339 so the comparison is
// text-to-text on SQLite (whose driver stores timestamps as RFC3339 strings)
// and coerces cleanly on MySQL/Postgres.
func cutoffStr(t time.Time) string { return t.Format(time.RFC3339) }

// SweepExpired enforces the two outbox clocks and reports both counts:
// pendingEvicted (rows past OutboxMaxAge whose delivery was abandoned) and
// deadPurged (dead-lettered rows past DeadLetterTTL). Neither touches
// audit_log — a delivery can be abandoned; a record cannot.
func (r *OutboxRepository) SweepExpired(ctx context.Context, now time.Time, outboxMaxAge, deadLetterTTL time.Duration) (pendingEvicted, deadPurged int, err error) {
	if outboxMaxAge <= 0 && deadLetterTTL <= 0 {
		return 0, 0, nil
	}
	var pending, dead int
	if deadLetterTTL > 0 && outboxMaxAge > 0 {
		row := r.db.QueryRowContext(ctx, outboxSweepExpired,
			cutoffStr(now.Add(-outboxMaxAge).UTC()), cutoffStr(now.Add(-deadLetterTTL).UTC()))
		if err := row.Scan(&pending, &dead); err != nil {
			return 0, 0, err
		}
	} else {
		// One clock disabled: count each class separately so the delete and
		// the report always agree.
		cond, args := outboxSingleClockCondition(outboxMaxAge, deadLetterTTL, now)
		var all int
		if err := r.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM audit_outbox WHERE "+cond, args...).Scan(&all); err != nil {
			return 0, 0, err
		}
		if outboxMaxAge > 0 {
			pending = all
		} else {
			dead = all
		}
	}
	if pending+dead == 0 {
		return 0, 0, nil
	}
	if deadLetterTTL > 0 && outboxMaxAge > 0 {
		if _, err := r.db.ExecContext(ctx, outboxSweepDelete,
			cutoffStr(now.Add(-outboxMaxAge).UTC()), cutoffStr(now.Add(-deadLetterTTL).UTC())); err != nil {
			return 0, 0, err
		}
		return pending, dead, nil
	}
	cond, args := outboxSingleClockCondition(outboxMaxAge, deadLetterTTL, now)
	if _, err := r.db.ExecContext(ctx,
		"DELETE FROM audit_outbox WHERE "+cond, args...); err != nil {
		return 0, 0, err
	}
	return pending, dead, nil
}

func outboxSingleClockCondition(maxAge, deadTTL time.Duration, now time.Time) (string, []any) {
	if maxAge > 0 {
		return "dead_lettered_at IS NULL AND created_at < $1", []any{cutoffStr(now.Add(-maxAge).UTC())}
	}
	return "dead_lettered_at IS NOT NULL AND dead_lettered_at < $1", []any{cutoffStr(now.Add(-deadTTL).UTC())}
}

// EvictOverCap is the OutboxMaxRows emergency valve: dead-lettered rows are
// shed first (already-lost deliveries cost no new harm), then the oldest
// pending rows. Everything evicted is reported so the caller counts it as
// delivery_dropped and — for pending rows — raises the loud signal.
//
// Candidates are selected then deleted by id: DELETE ... WHERE id IN
// (SELECT ... LIMIT n) is rejected by MySQL and self-referencing in every
// dialect, so the two-step form is the portable one.
func (r *OutboxRepository) EvictOverCap(ctx context.Context, maxRows int) (evicted int, pendingEvicted int, err error) {
	var total int
	if err := r.db.QueryRowContext(ctx, outboxCountTotal).Scan(&total); err != nil {
		return 0, 0, err
	}
	if total <= maxRows {
		return 0, 0, nil
	}
	overflow := total - maxRows

	// Dead-lettered rows first.
	deadIDs, err := r.selectIDs(ctx, outboxEvictDeadCandidates, overflow)
	if err != nil {
		return 0, 0, err
	}
	deadN, err := r.deleteIDs(ctx, deadIDs)
	if err != nil {
		return deadN, 0, err
	}
	remaining := overflow - deadN

	pendN := 0
	if remaining > 0 {
		pendIDs, err := r.selectIDs(ctx, outboxEvictCandidates, remaining)
		if err != nil {
			return deadN, 0, err
		}
		pendN, err = r.deleteIDs(ctx, pendIDs)
		if err != nil {
			return deadN, pendN, err
		}
	}
	return deadN + pendN, pendN, nil
}

// selectIDs runs one of the candidate queries above and collects the ids.
func (r *OutboxRepository) selectIDs(ctx context.Context, query string, limit int) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// deleteIDs removes the given rows one by one, returning how many were
// actually deleted (a concurrent dispatcher may have delivered some first).
func (r *OutboxRepository) deleteIDs(ctx context.Context, ids []string) (int, error) {
	deleted := 0
	for _, id := range ids {
		res, err := r.db.ExecContext(ctx, outboxDelete, id)
		if err != nil {
			return deleted, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			deleted++
		}
	}
	return deleted, nil
}

// InTx reports whether ctx carries an active transaction started by WithTx.
// Used by the audit write path: savepoints are only meaningful inside a
// transaction (Postgres errors on RELEASE SAVEPOINT outside one), and
// fail-closed is only meaningful where a rollback can abort the operation.
func (d *DB) InTx(ctx context.Context) bool {
	_, ok := txFromContext(ctx)
	return ok
}

// Savepoint runs fn inside a named savepoint on the current transaction or
// connection. A failed statement poisons a Postgres transaction — every later
// statement errors until rollback — so "log it and continue" is impossible
// without SAVEPOINT / ROLLBACK TO SAVEPOINT. Savepoints are portable across
// PostgreSQL, MySQL, and SQLite, so one path serves all three drivers.
//
// Without a surrounding transaction the savepoint is inert: the insert
// autocommits directly. Postgres only warns on a bare SAVEPOINT but errors on
// RELEASE SAVEPOINT outside a transaction block, so a no-tx path must not
// issue either — otherwise every post-commit record reports a failed insert.
func (d *DB) Savepoint(ctx context.Context, name string, fn func(ctx context.Context) error) error {
	if !d.InTx(ctx) {
		return fn(ctx)
	}
	if _, err := d.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
		return fmt.Errorf("savepoint %s: %w", name, err)
	}
	if err := fn(ctx); err != nil {
		// Discard the poisoned partial statement; the outer transaction
		// stays usable and the caller decides what the failure means.
		if _, rbErr := d.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+name); rbErr != nil {
			return errors.Join(err, fmt.Errorf("rollback to savepoint %s: %w", name, rbErr))
		}
		return err
	}
	if _, err := d.ExecContext(ctx, "RELEASE SAVEPOINT "+name); err != nil {
		return fmt.Errorf("release savepoint %s: %w", name, err)
	}
	return nil
}

// TableExists reports whether table is present. The durable write path checks
// audit_outbox at startup: the migration must ship before the new write path
// enables, or every durable insert fails (silently, under fail-open) until
// the table exists.
func (d *DB) TableExists(ctx context.Context, table string) (bool, error) {
	switch d.Driver() {
	case "postgres":
		row := d.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1", table)
		var n int
		if err := row.Scan(&n); err != nil {
			return false, err
		}
		return n > 0, nil
	case "mysql":
		row := d.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?", table)
		var n int
		if err := row.Scan(&n); err != nil {
			return false, err
		}
		return n > 0, nil
	default: // sqlite, sqlite3
		row := d.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table)
		var n int
		if err := row.Scan(&n); err != nil {
			return false, err
		}
		return n > 0, nil
	}
}

// RecordRepository writes audit_log rows in the caller's transaction. It
// replaces the old SQLAuditSink's write role: the record insert is no longer
// a sink running after commit in its own transaction — it joins the state
// change's transaction, which is what makes record-iff-commit hold.
type RecordRepository struct {
	db *DB
}

func NewRecordRepository(db *DB) *RecordRepository {
	return &RecordRepository{db: db}
}

var _ audit.RecordStore = (*RecordRepository)(nil)

// Insert writes one audit_log row, joining any transaction carried by ctx.
func (r *RecordRepository) Insert(ctx context.Context, e audit.Event) error {
	query := r.db.Rebind(`INSERT INTO audit_log (id, event_type, severity, success,
		actor_id, target_id, session_id, org_id, ip, user_agent, parsed_ua,
		request_id, correlation_id, metadata, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`)

	var metaJSON []byte
	if e.Metadata != nil {
		var err error
		if metaJSON, err = json.Marshal(e.Metadata); err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
	}

	var parsedUARaw []byte
	if e.ParsedUA != nil {
		stored := newStoredUserAgent(e.ParsedUA)
		if stored != nil {
			var err error
			if parsedUARaw, err = json.Marshal(stored); err != nil {
				return fmt.Errorf("marshal parsed_ua: %w", err)
			}
		}
	}

	ipStr := ""
	if e.IP != nil {
		ipStr = e.IP.String()
	}

	if _, err := r.db.ExecContext(ctx, query,
		e.ID, string(e.Type), string(e.Severity), e.Success,
		e.ActorID, e.TargetUserID, e.SessionID, e.OrgID,
		ipStr, e.UserAgent, parsedUARaw, e.RequestID, e.CorrelationID,
		metaJSON, e.CreatedAt.UTC(),
	); err != nil {
		return fmt.Errorf("audit record insert: %w", err)
	}
	return nil
}

// Cleanup deletes audit_log rows older than retentionDays — the compliance
// retention path, which deletes whole time ranges of records and never
// touches the outbox (delivery bookkeeping has its own clocks).
func (r *RecordRepository) Cleanup(ctx context.Context, retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	result, err := r.db.ExecContext(ctx, "DELETE FROM audit_log WHERE created_at < $1", cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}
