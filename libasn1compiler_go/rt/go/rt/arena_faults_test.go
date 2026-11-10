//go:build asn1cgo_faults

package rt

import "testing"

// Event 1 is arena_new itself, event 2 its first chunk. Failing the chunk
// must return NULL and leave the live-arena balance untouched.
func TestArenaNewChunkFailureKeepsBalance(t *testing.T) {
	defer ArenaFailAt(0)
	ArenaFailAt(2)
	if a := arenaNew(0); a != nil {
		arenaFree(a)
		t.Fatal("arena_new succeeded, want NULL on first-chunk failure")
	}
	if b := ArenaBalance(); b != 0 {
		t.Fatalf("ArenaBalance = %d after failed arena_new, want 0", b)
	}
	ArenaFailAt(0)
	a := arenaNew(0)
	if a == nil {
		t.Fatal("arena_new failed with injection off")
	}
	if ev := ArenaEvents(); ev != 2 {
		t.Errorf("ArenaEvents = %d, want 2", ev)
	}
	arenaFree(a)
	if b := ArenaBalance(); b != 0 {
		t.Fatalf("ArenaBalance = %d, want 0", b)
	}
}
