package tree

import (
	"flag"
	"reflect"
	"testing"
)

type IntVal int

func (i IntVal) Comp(val Val) int8 {
	v := val.(IntVal)
	if i > v {
		return 1
	} else if i < v {
		return -1
	} else {
		return 0
	}
}

func (i IntVal) Match(cond interface{}) int8 {
	// Unused
	return 0
}

type StringVal string

func (i StringVal) Comp(val Val) int8 {
	v := val.(StringVal)
	if i > v {
		return 1
	} else if i < v {
		return -1
	} else {
		return 0
	}
}

func (i StringVal) Match(cond interface{}) int8 {
	// Unused
	return 0
}

func btreeInOrder(n int) *Btree {
	btree := New()
	for i := 1; i <= n; i++ {
		btree.Insert(IntVal(i))
	}
	return btree
}

func btreeFixed(values []Val) *Btree {
	btree := New()
	btree.InsertAll(values)
	return btree
}

const benchLen = 1000000

var btreeDegree = flag.Int("degree", 32, "B-Tree degree")

func TestBtree_Get(t *testing.T) {
	values := []Val{IntVal(9), IntVal(4), IntVal(2), IntVal(6), IntVal(8), IntVal(0), IntVal(3), IntVal(1), IntVal(7), IntVal(5)}
	btree := btreeFixed(values).InsertAll(values)

	expect, actual := len(values), btree.Len()
	if actual != expect {
		t.Error("length should equal", expect, "actual", actual)
	}

	expect2 := IntVal(2)
	if btree.Get(expect2) != expect2 {
		t.Error("value should equal", expect2)
	}
}

func TestBtreeString_Get(t *testing.T) {
	tree := New()
	tree.Insert(StringVal("Oreto")).Insert(StringVal("Michael")).Insert(StringVal("Ross"))

	expect := StringVal("Ross")
	if tree.Get(expect) != expect {
		t.Error("value should equal", expect)
	}
}

func TestBtree_Contains(t *testing.T) {
	btree := btreeInOrder(1000)

	test := IntVal(1)
	if !btree.Contains(test) {
		t.Error("tree should contain", test)
	}

	test2 := []Val{IntVal(1), IntVal(2), IntVal(3), IntVal(4)}
	if !btree.ContainsAll(test2) {
		t.Error("tree should contain", test2)
	}

	test2 = []Val{IntVal(5)}
	if !btree.ContainsAny(test2) {
		t.Error("tree should contain", test2)
	}

	test2 = []Val{IntVal(5000), IntVal(2000)}
	if btree.ContainsAny(test2) {
		t.Error("tree should not contain any", test2)
	}
}

func TestBtree_String(t *testing.T) {
	btree := btreeFixed([]Val{IntVal(1), IntVal(2), IntVal(3), IntVal(4), IntVal(5), IntVal(6)})
	s1 := btree.String()
	s2 := "[1 2 3 4 5 6]"
	if s1 != s2 {
		t.Error(s1, "tree string representation should equal", s2)
	}
}

func TestBtree_Values(t *testing.T) {
	const capacity = 3
	btree := btreeFixed([]Val{IntVal(1), IntVal(2)})

	b := btree.Values()
	c := []Val{IntVal(1), IntVal(2)}
	if !reflect.DeepEqual(c, b) {
		t.Error(c, "should equal", b)
	}
	btree.Insert(IntVal(3))

	desc := [capacity]IntVal{}
	btree.Descend(func(n *Node, i int) bool {
		desc[i] = n.Value.(IntVal)
		return true
	})
	d := [capacity]IntVal{3, 2, 1}
	if !reflect.DeepEqual(desc, d) {
		t.Error(desc, "should equal", d)
	}

	e := []IntVal{1, 2, 3}
	for i, v := range btree.Values() {
		if e[i] != v {
			t.Error(e[i], "should equal", v)
		}
	}
}

func TestBtree_Delete(t *testing.T) {
	test := []Val{IntVal(1), IntVal(2), IntVal(3)}
	btree := btreeFixed(test)

	btree.DeleteAll(test)

	if !btree.Empty() {
		t.Error("tree should be empty")
	}

	btree = btreeFixed(test)
	pop := btree.Pop()
	if pop != IntVal(3) {
		t.Error(pop, "should be 3")
	}
	pull := btree.Pull()
	if pull != IntVal(1) {
		t.Error(pop, "should be 3")
	}
	if !btree.Delete(btree.Pop()).Empty() {
		t.Error("tree should be empty")
	}
	btree.Pop()
	btree.Pull()
}

func TestBtree_HeadTail(t *testing.T) {
	btree := btreeFixed([]Val{IntVal(1), IntVal(2), IntVal(3)})
	if btree.Head() != IntVal(1) {
		t.Error("head element should be 1")
	}
	if btree.Tail() != IntVal(3) {
		t.Error("head element should be 3")
	}
	btree.Init()
	if btree.Head() != nil {
		t.Error("head element should be nil")
	}
}

type TestKey1 struct {
	Name string
}

func (testkey TestKey1) Comp(val Val) int8 {
	var c int8
	tk := val.(TestKey1)
	if testkey.Name > tk.Name {
		c = 1
	} else if testkey.Name < tk.Name {
		c = -1
	}
	return c
}

func (testkey TestKey1) Match(cond interface{}) int8 {
	// Unused
	return 0
}

func TestBtree_CustomKey(t *testing.T) {
	btree := New()
	btree.InsertAll([]Val{TestKey1{Name: "Ross"}, TestKey1{Name: "Michael"},
		TestKey1{Name: "Angelo"}, TestKey1{Name: "Jason"}})

	rootName := btree.root.Value.(TestKey1).Name
	if btree.root.Value.(TestKey1).Name != "Michael" {
		t.Error(rootName, "should equal Michael")
	}
	btree.Init()
	btree.InsertAll([]Val{TestKey1{Name: "Ross"}, TestKey1{Name: "Michael"},
		TestKey1{Name: "Angelo"}, TestKey1{Name: "Jason"}})
	btree.Debug()
	s := btree.String()
	test := "[{Angelo} {Jason} {Michael} {Ross}]"
	if s != test {
		t.Error(s, "should equal", test)
	}

	btree.Delete(TestKey1{Name: "Michael"})
	if btree.Len() != 3 {
		t.Error("tree length should be 3")
	}
	test = "Jason"
	if btree.root.Value.(TestKey1).Name != test {
		t.Error(btree.root.Value, "root of the tree should be", test)
	}
	for !btree.Empty() {
		btree.Delete(btree.root.Value)
	}
	btree.Debug()
}

func TestBtree_Duplicates(t *testing.T) {
	btree := New()
	btree.InsertAll([]Val{IntVal(0), IntVal(2), IntVal(5), IntVal(10), IntVal(15), IntVal(20), IntVal(12), IntVal(14),
		IntVal(13), IntVal(25), IntVal(0), IntVal(2), IntVal(5), IntVal(10), IntVal(15), IntVal(20), IntVal(12), IntVal(14), IntVal(13), IntVal(25)})
	test := 10
	length := btree.Len()
	if length != test {
		t.Error(length, "tree length should be", test)
	}
}
