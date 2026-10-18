//go:build darwin

package engine

import (
	"testing"
	"time"
)

func TestReadCountersDarwin(t *testing.T) {
	total, names := readCountersDarwin(nil)
	if len(total) == 0 {
		t.Skip("no active interfaces reported by the ifmib sysctl")
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

// macOS ifmib counters are 32-bit and wrap around ~4 GiB; safeDelta must
// bridge a wrap that happens between two samples.
func TestSafeDeltaHandles32BitWrap(t *testing.T) {
	const before = uint64(0xffffff00)
	const after = uint64(0x00000100) // wrapped past 2^32
	if got := safeDelta(before, after); got != 0x200 {
		t.Errorf("safeDelta(0x%x, 0x%x) = 0x%x, want 0x200", before, after, got)
	}
}
