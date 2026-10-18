//go:build darwin

package engine

import (
	"testing"
	"time"
)

func TestReadCountersDarwin(t *testing.T) {
	total, names := readCountersDarwin(nil)
	if len(total) == 0 {
		t.Skip("no active interfaces reported by the ifdata sysctl")
	}
	for _, name := range names {
		if name == "lo0" {
			t.Fatalf("loopback interface lo0 must be excluded, got %v", names)
		}
	}

	// Counters are cumulative: a second read must not go backwards.
	time.Sleep(50 * time.Millisecond)
	again, _ := readCountersDarwin(nil)
	for name, c := range total {
		c2, ok := again[name]
		if !ok {
			continue // interface vanished between reads; nothing to assert
		}
		if c2.rx < c.rx || c2.tx < c.tx {
			t.Errorf("%s counters went backwards: rx %d -> %d, tx %d -> %d",
				name, c.rx, c2.rx, c.tx, c2.tx)
		}
	}
}
