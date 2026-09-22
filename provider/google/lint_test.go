package google

import (
	"strings"
	"testing"
)

type testErrorChecker struct {
	t testing.TB
}

func checkTestErrors(t testing.TB) testErrorChecker {
	t.Helper()
	return testErrorChecker{t: t}
}

func (c testErrorChecker) noError(err error) {
	c.t.Helper()
	if err != nil {
		c.t.Errorf("unexpected error: %v", err)
	}
}

func (c testErrorChecker) result(_ any, err error) {
	c.t.Helper()
	if err != nil {
		c.t.Errorf("unexpected error: %v", err)
	}
}

func testOAuthValue(parts ...string) string {
	return strings.Join(parts, "-")
}
