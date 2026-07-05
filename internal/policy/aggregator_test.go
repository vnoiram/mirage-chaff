package policy

import "testing"

func TestAggregatorBoundedLRU(t *testing.T) {
	a := newAggregator(2)

	a.record("a.test", "/1")
	a.record("b.test", "/2")
	a.record("a.test", "/1") // bump a -> most recently seen
	a.record("c.test", "/3") // full: evicts LRU, which is b

	top := a.top(0)
	if len(top) != 2 {
		t.Fatalf("aggregator holds %d entries, want 2", len(top))
	}
	seen := map[string]int64{}
	for _, e := range top {
		seen[e.Domain] = e.Count
	}
	if _, ok := seen["b.test"]; ok {
		t.Error("least-recently-seen entry (b.test) should have been evicted")
	}
	if seen["a.test"] != 2 {
		t.Errorf("a.test count = %d, want 2", seen["a.test"])
	}
	if _, ok := seen["c.test"]; !ok {
		t.Error("most-recent entry (c.test) must be retained")
	}
}

func TestAggregatorTopOrdersByCount(t *testing.T) {
	a := newAggregator(10)
	a.record("hi.test", "/x")
	a.record("hi.test", "/x")
	a.record("lo.test", "/y")

	top := a.top(0)
	if top[0].Domain != "hi.test" || top[0].Count != 2 {
		t.Fatalf("top[0] = %+v, want hi.test count 2", top[0])
	}
}
