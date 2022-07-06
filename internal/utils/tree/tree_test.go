package tree

import (
	"testing"
)

type interval struct {
	start, end int
}

func (i *interval) Comp(other Val) int8 {
	ot := other.(*interval)
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

func (i *interval) Match(cond interface{}) int8 {
	if n, ok := cond.(*interval); ok {
		// check if there is an overlap
		if i.start <= n.end && i.end >= n.start {
			return 0
		}
		if i.start > n.end {
			return 1
		} else {
			return -1
		}
	} else {
		panic("invalid cond type")
	}
}

func TestBtree(t *testing.T) {
	values := []Val{
		&interval{start: 9, end: 10},
		&interval{start: 3, end: 4},
		&interval{start: 1, end: 2},
		&interval{start: 5, end: 6},
		&interval{start: 7, end: 8},
		&interval{start: 20, end: 100},
		&interval{start: 11, end: 12},
	}
	btree := New()
	btree.InsertAll(values)

	expect, actual := len(values), btree.Len()
	if actual != expect {
		t.Error("length should equal", expect, "actual", actual)
	}

	rs := btree.Match(&interval{start: 1, end: 6})
	if len(rs) != 3 {
		t.Errorf("expected 3 results, got %d", len(rs))
	}
	if rs[0].(*interval).start != 1 || rs[0].(*interval).end != 2 {
		t.Errorf("expected result 1 to be [1, 2], got %v", rs[0])
	}
	if rs[1].(*interval).start != 3 || rs[1].(*interval).end != 4 {
		t.Errorf("expected result 2 to be [3, 4], got %v", rs[1])
	}
	if rs[2].(*interval).start != 5 || rs[2].(*interval).end != 6 {
		t.Errorf("expected result 3 to be [5, 6], got %v", rs[2])
	}

	btree.Delete(&interval{start: 5, end: 6})

	rs = btree.Match(&interval{start: 1, end: 6})
	if len(rs) != 2 {
		t.Errorf("expected 2 results, got %d", len(rs))
	}
	if rs[0].(*interval).start != 1 || rs[0].(*interval).end != 2 {
		t.Errorf("expected result 1 to be [1, 2], got %v", rs[0])
	}
	if rs[1].(*interval).start != 3 || rs[1].(*interval).end != 4 {
		t.Errorf("expected result 2 to be [3, 4], got %v", rs[1])
	}

	btree.Delete(&interval{start: 11, end: 12})

	rs = btree.Match(&interval{start: 12, end: 19})
	if len(rs) != 0 {
		t.Errorf("expected 0 results, got %d", len(rs))
	}

	expect, actual = len(values)-2, btree.Len()
	if actual != expect {
		t.Error("length should equal", expect, "actual", actual)
	}
}
