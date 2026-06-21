package validate

import "testing"

// TestAllCategoriesSortedUnique guards the AllCategories list: it must be
// non-empty, sorted, and free of duplicates. A duplicate usually means a
// copy-paste slip when adding a category; an out-of-order entry means the
// -list-categories output and the derived error message would be misordered.
func TestAllCategoriesSortedUnique(t *testing.T) {
	cats := AllCategories()
	if len(cats) == 0 {
		t.Fatal("AllCategories() is empty")
	}
	seen := make(map[string]bool, len(cats))
	for i, c := range cats {
		if c == "" {
			t.Errorf("AllCategories()[%d] is empty", i)
		}
		if seen[c] {
			t.Errorf("AllCategories() has duplicate %q", c)
		}
		seen[c] = true
		if i > 0 && cats[i-1] > c {
			t.Errorf("AllCategories() not sorted: %q before %q", cats[i-1], c)
		}
	}
}
