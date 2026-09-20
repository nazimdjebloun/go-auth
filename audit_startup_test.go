package goauth

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	_ "modernc.org/sqlite"
)

type startupBoundedSink struct{}

func (startupBoundedSink) Handle(context.Context, audit.Event) error        { return nil }
func (startupBoundedSink) HandleBatch(context.Context, []audit.Event) error { return nil }
func (startupBoundedSink) MaxBatchDeliveryTime(int) (time.Duration, bool) {
	return time.Second, true
}

func TestStartAuditServiceRejectsMissingOutboxMigration(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := Config{audit: AuditConfig{
		Enabled: true,
		Sinks:   []audit.EventSink{startupBoundedSink{}},
	}}
	svc, pub, err := startAuditService(&cfg, sqlstore.NewDB(db, "sqlite"))
	if err == nil || !strings.Contains(err.Error(), "audit_outbox table is missing") {
		t.Fatalf("startAuditService error = %v, want missing migration error", err)
	}
	if svc != nil || pub != nil {
		t.Fatalf("service started despite missing migration: svc=%v pub=%v", svc, pub)
	}
}
