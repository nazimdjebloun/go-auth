package emailtemplate

import (
	"testing"
	"time"
)

// FuzzFormatDuration drives the human-readable duration formatter with every
// possible nanosecond value. The output feeds email copy ("Your code expires
// in 10 minutes"), so it must never come out empty — including for negative
// durations and values at the extremes of the int64 range, where the hour and
// minute arithmetic can otherwise overflow into nonsense.
func FuzzFormatDuration(f *testing.F) {
	for _, d := range []time.Duration{
		0,
		time.Nanosecond,
		time.Minute,
		2 * time.Minute,
		time.Hour,
		-time.Minute,
		24*time.Hour + 30*time.Minute,
		time.Duration(1) << 62,
		-(time.Duration(1) << 62),
	} {
		f.Add(int64(d))
	}
	f.Fuzz(func(t *testing.T, ns int64) {
		out := FormatDuration(time.Duration(ns))
		if out == "" {
			t.Errorf("FormatDuration(%d) returned an empty string", ns)
		}
	})
}
