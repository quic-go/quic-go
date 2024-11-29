package tree

import (
	"testing"
)

type interval struct {
	start, end int
}

func (i interval) Comp(ot interval) int8 {
	if i.start < ot.start {
		return -1
	}
	if i.start > ot.start {
		return 1
	}
	if i.end < ot.end {
		return -1
	}
	if i.end > ot.end {
		return 1
	}
	return 0
}

func (i interval) Match(ot interval) int8 {
	// check if there is an overlap
	if i.start <= ot.end && i.end >= ot.start {
		return 0
	}
	if i.start > ot.end {
		return 1
	} else {
		return -1
	}
}

func TestBtree(t *testing.T) {
	values := []interval{
		{start: 9, end: 10},
		{start: 3, end: 4},
		{start: 1, end: 2},
		{start: 5, end: 6},
		{start: 7, end: 8},
		{start: 20, end: 100},
		{start: 11, end: 12},
	}
	btree := New[interval]()
	btree.InsertAll(values)

	expect, actual := len(values), btree.Len()
	if actual != expect {
		t.Error("length should equal", expect, "actual", actual)
	}

	rs := btree.Match(interval{start: 1, end: 6})
	if len(rs) != 3 {
		t.Errorf("expected 3 results, got %d", len(rs))
	}
	if rs[0].start != 1 || rs[0].end != 2 {
		t.Errorf("expected result 1 to be [1, 2], got %v", rs[0])
	}
	if rs[1].start != 3 || rs[1].end != 4 {
		t.Errorf("expected result 2 to be [3, 4], got %v", rs[1])
	}
	if rs[2].start != 5 || rs[2].end != 6 {
		t.Errorf("expected result 3 to be [5, 6], got %v", rs[2])
	}

	btree.Delete(interval{start: 5, end: 6})

	rs = btree.Match(interval{start: 1, end: 6})
	if len(rs) != 2 {
		t.Errorf("expected 2 results, got %d", len(rs))
	}
	if rs[0].start != 1 || rs[0].end != 2 {
		t.Errorf("expected result 1 to be [1, 2], got %v", rs[0])
	}
	if rs[1].start != 3 || rs[1].end != 4 {
		t.Errorf("expected result 2 to be [3, 4], got %v", rs[1])
	}

	btree.Delete(interval{start: 11, end: 12})

	rs = btree.Match(interval{start: 12, end: 19})
	if len(rs) != 0 {
		t.Errorf("expected 0 results, got %d", len(rs))
	}

	expect, actual = len(values)-2, btree.Len()
	if actual != expect {
		t.Error("length should equal", expect, "actual", actual)
	}
}
