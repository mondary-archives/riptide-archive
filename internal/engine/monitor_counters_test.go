package engine

import "testing"

// The Windows engine reports 32-bit counters that wrap around ~4 GiB;
// safeDelta must bridge a wrap that happens between two samples.
func TestSafeDeltaHandles32BitWrap(t *testing.T) {
	const before = uint64(0xffffff00)
	const after = uint64(0x00000100) // wrapped past 2^32
	if got := safeDelta(before, after); got != 0x200 {
		t.Errorf("safeDelta(0x%x, 0x%x) = 0x%x, want 0x200", before, after, got)
	}
}
