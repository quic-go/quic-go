package utils

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils/tree"
)

// ByteInterval is an interval from one ByteCount to the other
type ByteInterval struct {
	Start protocol.ByteCount
	End   protocol.ByteCount
}

func (i *ByteInterval) Comp(val tree.Val) int8 {
	v := val.(*ByteInterval)
	if i.Start < v.Start {
		return -1
	}
	if i.Start > v.Start {
		return 1
	}
	if i.End < v.End {
		return -1
	}
	if i.End > v.End {
		return 1
	}
	return 0
}

func (i *ByteInterval) Match(cond interface{}) int8 {
	n := cond.(*ByteInterval)
	// check if there is an overlap
	if i.Start <= n.End && i.End >= n.Start {
		return 0
	}
	if i.Start > n.End {
		return 1
	} else {
		return -1
	}
}

func (i *ByteInterval) String() string {
	return fmt.Sprintf("[%d, %d]", i.Start, i.End)
}
