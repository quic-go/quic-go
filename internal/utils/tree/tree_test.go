package tree

import (
	"reflect"
	"testing"
)

type IntVal int

func (i IntVal) Comp(v IntVal) int8 {
	if i > v {
		return 1
	} else if i < v {
		return -1
	} else {
		return 0
	}
}

func (i IntVal) Match(v IntVal) int8 {
	// Unused
	return 0
}

type StringVal string

func (i StringVal) Comp(v StringVal) int8 {
	if i > v {
		return 1
	} else if i < v {
		return -1
	} else {
		return 0
	}
}

func (i StringVal) Match(v StringVal) int8 {
	// Unused
	return 0
}

func btreeInOrder(n int) *Btree[IntVal] {
	btree := New[IntVal]()
	for i := 1; i <= n; i++ {
		btree.Insert(IntVal(i))
	}
	return btree
}

func btreeFixed[T Val[T]](values []T) *Btree[T] {
	btree := New[T]()
	btree.InsertAll(values)
	return btree
}

func TestBtree_Get(t *testing.T) {
	values := []IntVal{9, 4, 2, 6, 8, 0, 3, 1, 7, 5}
	btree := btreeFixed[IntVal](values).InsertAll(values)

	expect, actual := len(values), btree.Len()
	if actual != expect {
		t.Error("length should equal", expect, "actual", actual)
	}

	expect2 := IntVal(2)
	if btree.Get(expect2) == nil || *btree.Get(expect2) != expect2 {
		t.Error("value should equal", expect2)
	}
}

func TestBtreeString_Get(t *testing.T) {
	tree := New[StringVal]()
	tree.Insert("Oreto").Insert("Michael").Insert("Ross")

	expect := StringVal("Ross")
	if tree.Get(expect) == nil || *tree.Get(expect) != expect {
		t.Error("value should equal", expect)
	}
}

func TestBtree_Contains(t *testing.T) {
	btree := btreeInOrder(1000)

	test := IntVal(1)
	if !btree.Contains(test) {
		t.Error("tree should contain", test)
	}

	test2 := []IntVal{1, 2, 3, 4}
	if !btree.ContainsAll(test2) {
		t.Error("tree should contain", test2)
	}

	test2 = []IntVal{5}
	if !btree.ContainsAny(test2) {
		t.Error("tree should contain", test2)
	}

	test2 = []IntVal{5000, 2000}
	if btree.ContainsAny(test2) {
		t.Error("tree should not contain any", test2)
	}
}

func TestBtree_String(t *testing.T) {
	btree := btreeFixed[IntVal]([]IntVal{1, 2, 3, 4, 5, 6})
	s1 := btree.String()
	s2 := "[1 2 3 4 5 6]"
	if s1 != s2 {
		t.Error(s1, "tree string representation should equal", s2)
	}
}

func TestBtree_Values(t *testing.T) {
	const capacity = 3
	btree := btreeFixed[IntVal]([]IntVal{1, 2})

	b := btree.Values()
	c := []IntVal{1, 2}
	if !reflect.DeepEqual(c, b) {
		t.Error(c, "should equal", b)
	}
	btree.Insert(IntVal(3))

	desc := [capacity]IntVal{}
	btree.Descend(func(n *Node[IntVal], i int) bool {
		desc[i] = n.Value
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
	test := []IntVal{1, 2, 3}
	btree := btreeFixed(test)

	btree.DeleteAll(test)

	if !btree.Empty() {
		t.Error("tree should be empty")
	}

	btree = btreeFixed(test)
	pop := btree.Pop()
	if pop == nil || *pop != IntVal(3) {
		t.Error(pop, "should be 3")
	}
	pull := btree.Pull()
	if pull == nil || *pull != IntVal(1) {
		t.Error(pop, "should be 3")
	}
	if !btree.Delete(*btree.Pop()).Empty() {
		t.Error("tree should be empty")
	}
	btree.Pop()
	btree.Pull()
}

func TestBtree_HeadTail(t *testing.T) {
	btree := btreeFixed[IntVal]([]IntVal{1, 2, 3})
	if btree.Head() == nil || *btree.Head() != IntVal(1) {
		t.Error("head element should be 1")
	}
	if btree.Tail() == nil || *btree.Tail() != IntVal(3) {
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

func (testkey TestKey1) Comp(tk TestKey1) int8 {
	var c int8
	if testkey.Name > tk.Name {
		c = 1
	} else if testkey.Name < tk.Name {
		c = -1
	}
	return c
}

func (testkey TestKey1) Match(tk TestKey1) int8 {
	// Unused
	return 0
}

func TestBtree_CustomKey(t *testing.T) {
	btree := New[TestKey1]()
	btree.InsertAll([]TestKey1{
		{Name: "Ross"},
		{Name: "Michael"},
		{Name: "Angelo"},
		{Name: "Jason"},
	})

	rootName := btree.root.Value.Name
	if btree.root.Value.Name != "Michael" {
		t.Error(rootName, "should equal Michael")
	}
	btree.Init()
	btree.InsertAll([]TestKey1{
		{Name: "Ross"},
		{Name: "Michael"},
		{Name: "Angelo"},
		{Name: "Jason"},
	})
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
	if btree.root.Value.Name != test {
		t.Error(btree.root.Value, "root of the tree should be", test)
	}
	for !btree.Empty() {
		btree.Delete(btree.root.Value)
	}
	btree.Debug()
}

func TestBtree_Duplicates(t *testing.T) {
	btree := New[IntVal]()
	btree.InsertAll([]IntVal{
		0, 2, 5, 10, 15, 20, 12, 14,
		13, 25, 0, 2, 5, 10, 15, 20, 12, 14, 13, 25,
	})
	test := 10
	length := btree.Len()
	if length != test {
		t.Error(length, "tree length should be", test)
	}
}
