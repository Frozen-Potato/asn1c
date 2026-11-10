package rt

import (
	"sync"
	"testing"
)

// Many goroutines create, fill (forcing chunk growth) and free arenas; the
// balance must be exactly 0 once all calls have returned.
func TestArenaConcurrentBalance(t *testing.T) {
	const workers, iters = 16, 500
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				a := arenaNew(64)
				if a == nil {
					t.Error("arena_new returned NULL")
					return
				}
				for j := 0; j < 8; j++ {
					if !arenaAlloc(a, 100, 8) {
						t.Error("arena_alloc returned NULL")
					}
				}
				_ = ArenaBalance() // concurrent read must be safe
				arenaFree(a)
			}
		}()
	}
	wg.Wait()
	if b := ArenaBalance(); b != 0 {
		t.Fatalf("ArenaBalance = %d, want 0", b)
	}
}
