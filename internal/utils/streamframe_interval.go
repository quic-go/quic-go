package utils

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// ByteInterval is an interval from one ByteCount to the other
type ByteInterval struct {
	Start protocol.ByteCount
	End   protocol.ByteCount
}

func (i ByteInterval) Comp(v ByteInterval) int8 {
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

func (i ByteInterval) Match(n ByteInterval) int8 {
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

func (i ByteInterval) String() string {
	return fmt.Sprintf("[%d, %d]", i.Start, i.End)
}
