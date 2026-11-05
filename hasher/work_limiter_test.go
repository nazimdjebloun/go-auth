package hasher

import (
	"errors"
	"sync"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
)

func TestNewWorkLimiter(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		want  int
	}{
		{"default", 0, 4},
		{"explicit", 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := NewWorkLimiter(tc.limit)
			if err != nil || l.Limit() != tc.want {
				t.Fatalf("NewWorkLimiter(%d) = %v, %v; want limit %d", tc.limit, l, err, tc.want)
			}
		})
	}
	if _, err := NewWorkLimiter(-1); err == nil {
		t.Fatal("negative concurrency accepted")
	}
}

func TestWorkLimiterRejectsExcessAndRecovers(t *testing.T) {
	l, err := NewWorkLimiter(2)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var workers sync.WaitGroup
	var unblock sync.Once
	t.Cleanup(func() {
		unblock.Do(func() { close(release) })
		workers.Wait()
	})
	for range 2 {
		workers.Go(func() {
			if err := l.Do(func() error {
				entered <- struct{}{}
				<-release
				return nil
			}); err != nil {
				t.Errorf("admitted work: %v", err)
			}
		})
	}
	for range 2 {
		<-entered
	}
	if err := l.Do(func() error {
		t.Error("overloaded work was invoked")
		return nil
	}); !errors.Is(err, domain.ErrPasswordWorkBusy) {
		t.Fatalf("overload = %v", err)
	}
	unblock.Do(func() { close(release) })
	workers.Wait()
	if err := l.Do(func() error { return nil }); err != nil {
		t.Fatalf("capacity was not released: %v", err)
	}
}

func TestWorkLimiterReleasesOnErrorAndPanic(t *testing.T) {
	l, err := NewWorkLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("hasher failed")
	if err := l.Do(func() error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("lost callback error: %v", err)
	}
	func() {
		defer func() {
			if recover() != failure {
				t.Error("callback panic was not propagated")
			}
		}()
		_ = l.Do(func() error { panic(failure) })
	}()
	if err := l.Do(func() error { return nil }); err != nil {
		t.Fatalf("capacity leaked after error/panic: %v", err)
	}
}

func TestWorkLimiterZeroValueFailsClosed(t *testing.T) {
	for _, l := range []*WorkLimiter{nil, {}} {
		if err := l.Do(func() error {
			t.Error("invalid limiter ran work")
			return nil
		}); err == nil {
			t.Fatal("invalid limiter accepted")
		}
	}
}
