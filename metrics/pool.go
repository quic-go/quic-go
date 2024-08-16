package metrics

import (
	"fmt"
	"sync"
)

const capacity = 4

// The stringPool is used to avoid allocations when passing labels to Prometheus.
var stringPool = sync.Pool{New: func() any {
	s := make([]string, 0, capacity)
	return &s
}}

func getStringSlice() *[]string {
	s := stringPool.Get().(*[]string)
	*s = (*s)[:0]
	return s
}

func putStringSlice(s *[]string) {
	if c := cap(*s); c < capacity {
		panic(fmt.Sprintf("unexpected slice cap: %d", c))
	}
	stringPool.Put(s)
}
