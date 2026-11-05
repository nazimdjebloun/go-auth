package hasher

import (
	"errors"

	"github.com/nazimdjebloun/go-auth/domain"
)

// DefaultPasswordConcurrency is the default maximum number of active password
// operations per Auth instance. It bounds work, not total process memory.
const DefaultPasswordConcurrency = 4

// WorkLimiter bounds concurrent password hashing and verification. Share one
// limiter across Auth instances when they draw on the same resource budget.
// Construct it with NewWorkLimiter; a zero-value WorkLimiter is invalid.
type WorkLimiter struct {
	slots chan struct{}
}

// NewWorkLimiter creates a limiter. Zero selects DefaultPasswordConcurrency;
// negative limits are invalid. Excess work is rejected without waiting.
func NewWorkLimiter(maxConcurrent int) (*WorkLimiter, error) {
	if maxConcurrent < 0 {
		return nil, errors.New("password concurrency must be nonnegative")
	}
	if maxConcurrent == 0 {
		maxConcurrent = DefaultPasswordConcurrency
	}
	return &WorkLimiter{slots: make(chan struct{}, maxConcurrent)}, nil
}

// Limit returns the configured concurrency, or zero for an invalid limiter.
func (l *WorkLimiter) Limit() int {
	if l == nil {
		return 0
	}
	return cap(l.slots)
}

// Do runs work synchronously if capacity is available, otherwise returning
// domain.ErrPasswordWorkBusy without invoking work. Capacity remains held until
// work returns or panics; callers must not recursively acquire the same limiter.
func (l *WorkLimiter) Do(work func() error) error {
	if l.Limit() == 0 {
		return errors.New("password work limiter must be constructed with NewWorkLimiter")
	}
	select {
	case l.slots <- struct{}{}:
		defer func() { <-l.slots }()
		return work()
	default:
		return domain.ErrPasswordWorkBusy
	}
}
