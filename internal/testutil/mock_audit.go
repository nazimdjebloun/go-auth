package testutil

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// MockAuditPublisher implements service.AuditPublisher by recording every
// event — for tests asserting a service call did (or didn't) record, without
// spinning up the real storage/dispatcher pipeline.
type MockAuditPublisher struct {
	mu     sync.Mutex
	Events []audit.Event
}

func NewMockAuditPublisher() *MockAuditPublisher {
	return &MockAuditPublisher{}
}

func (m *MockAuditPublisher) Record(_ context.Context, event audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, event)
	return nil
}

// ─── mockAuditLogRepo ──────────────────────────────────────────────

type MockAuditLogRepo struct {
	mu      sync.Mutex
	entries []port.AuditLogEntry
}

func NewMockAuditLogRepo() *MockAuditLogRepo {
	return &MockAuditLogRepo{}
}

// AddEntry seeds a row directly — tests exercising List/CountByDay don't
// need the real audit publisher pipeline wired up.
func (m *MockAuditLogRepo) AddEntry(e port.AuditLogEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
}

func (m *MockAuditLogRepo) List(_ context.Context, filter port.AuditLogFilter) ([]port.AuditLogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var matched []port.AuditLogEntry
	for _, e := range m.entries {
		if auditEntryMatchesFilter(e, filter) {
			matched = append(matched, e)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].CreatedAt.After(matched[j].CreatedAt) })

	if filter.Limit <= 0 {
		return matched, nil
	}
	start := filter.Offset
	if start > len(matched) {
		start = len(matched)
	}
	end := start + filter.Limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], nil
}

func (m *MockAuditLogRepo) Count(_ context.Context, filter port.AuditLogFilter) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.entries {
		if auditEntryMatchesFilter(e, filter) {
			n++
		}
	}
	return n, nil
}

func (m *MockAuditLogRepo) GetByID(_ context.Context, id string) (*port.AuditLogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.ID == id {
			cp := e
			return &cp, nil
		}
	}
	return nil, nil
}

// CountByDay groups matched entries by CreatedAt day — a small in-memory
// stand-in for the real GROUP BY date_trunc('day', ...) query.
func (m *MockAuditLogRepo) CountByDay(_ context.Context, filter port.AuditLogFilter) ([]port.DailyCount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	byDay := make(map[time.Time]int)
	for _, e := range m.entries {
		if !auditEntryMatchesFilter(e, filter) {
			continue
		}
		day := time.Date(e.CreatedAt.Year(), e.CreatedAt.Month(), e.CreatedAt.Day(), 0, 0, 0, 0, time.UTC)
		byDay[day]++
	}

	counts := make([]port.DailyCount, 0, len(byDay))
	for day, count := range byDay {
		counts = append(counts, port.DailyCount{Date: day, Count: count})
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i].Date.Before(counts[j].Date) })
	return counts, nil
}

func auditEntryMatchesFilter(e port.AuditLogEntry, filter port.AuditLogFilter) bool {
	if len(filter.Types) > 0 && !slices.Contains(filter.Types, e.Type) {
		return false
	}
	if filter.ActorID != nil && (e.ActorID == nil || *e.ActorID != *filter.ActorID) {
		return false
	}
	if filter.TargetUserID != nil && (e.TargetUserID == nil || *e.TargetUserID != *filter.TargetUserID) {
		return false
	}
	if filter.SessionID != nil && (e.SessionID == nil || *e.SessionID != *filter.SessionID) {
		return false
	}
	if filter.OrgID != nil && (e.OrgID == nil || *e.OrgID != *filter.OrgID) {
		return false
	}
	if filter.DeviceType != nil && *filter.DeviceType != "" {
		var ua domain.UserAgentInfo
		if err := json.Unmarshal(e.ParsedUA, &ua); err != nil || ua.DeviceType != *filter.DeviceType {
			return false
		}
	}
	if filter.IP != nil && *filter.IP != "" && e.IP != *filter.IP {
		return false
	}
	if filter.Success != nil && e.Success != *filter.Success {
		return false
	}
	if filter.FromDate != nil && e.CreatedAt.Before(*filter.FromDate) {
		return false
	}
	if filter.ToDate != nil && e.CreatedAt.After(*filter.ToDate) {
		return false
	}
	if filter.Search != nil && *filter.Search != "" {
		s := strings.ToLower(*filter.Search)
		matches := strings.Contains(strings.ToLower(e.UserAgent), s) ||
			strings.Contains(strings.ToLower(string(e.Metadata)), s) ||
			strings.Contains(strings.ToLower(e.IP), s) ||
			strings.Contains(strings.ToLower(e.Type), s)
		if !matches {
			return false
		}
	}
	return true
}
